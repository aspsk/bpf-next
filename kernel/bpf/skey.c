// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Isovalent
 */

#include <linux/bpf.h>

bool bpf_jit_supports_static_keys(void)
{
	int err;

	/* Should return -EINVAL if supported */
	err = bpf_arch_poke_static_branch(NULL, NULL, false);
	return err != -EOPNOTSUPP;
}

struct bpf_static_branch *bpf_static_branch_by_offset(struct bpf_prog *bpf_prog, u32 offset)
{
	u32 i, n = bpf_prog->aux->static_branches_len;
	struct bpf_static_branch *branch;

	for (i = 0; i < n; i++) {
		branch = &bpf_prog->aux->static_branches[i];
		if (branch->bpf_offset == offset)
			return branch;
	}
	return NULL;
}

static int bpf_prog_update_static_branches(struct bpf_prog *prog,
					   const struct bpf_map *map, bool on)
{
	struct bpf_static_branch *branch;
	int err = 0;
	int i;

	for (i = 0; i < prog->aux->static_branches_len; i++) {
		branch = &prog->aux->static_branches[i];
		if (branch->map != map)
			continue;

		err = bpf_arch_poke_static_branch(prog, branch, on);
		if (err)
			break;
	}

	return err;
}

static int static_key_add_prog(struct bpf_map *map, struct bpf_prog *prog)
{
	struct bpf_prog_aux_list_elem *elem;
	u32 key = 0;
	int err = 0;
	u32 *val;

	mutex_lock(&map->static_key_mutex);

	val = map->ops->map_lookup_elem(map, &key);
	if (!val) {
		err = -ENOENT;
		goto unlock_ret;
	}

	list_for_each_entry(elem, &map->static_key_list_head, list)
		if (elem->aux == prog->aux)
			goto unlock_ret;

	elem = kmalloc(sizeof(*elem), GFP_KERNEL);
	if (!elem) {
		err = -ENOMEM;
		goto unlock_ret;
	}

	INIT_LIST_HEAD(&elem->list);
	elem->aux = prog->aux;

	list_add_tail(&elem->list, &map->static_key_list_head);

	err = bpf_prog_update_static_branches(prog, map, *val);

unlock_ret:
	mutex_unlock(&map->static_key_mutex);
	return err;
}

void bpf_static_key_remove_prog(struct bpf_map *map, struct bpf_prog_aux *aux)
{
	struct bpf_prog_aux_list_elem *elem, *tmp;

	mutex_lock(&map->static_key_mutex);
	list_for_each_entry_safe(elem, tmp, &map->static_key_list_head, list) {
		if (elem->aux == aux) {
			list_del_init(&elem->list);
			kfree(elem);
			break;
		}
	}
	mutex_unlock(&map->static_key_mutex);
}

int bpf_static_key_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct bpf_prog_aux_list_elem *elem;
	bool on = *(u32 *)value;
	int err;

	mutex_lock(&map->static_key_mutex);

	err = map->ops->map_update_elem(map, key, value, flags);
	if (err)
		goto unlock_ret;

	list_for_each_entry(elem, &map->static_key_list_head, list) {
		err = bpf_prog_update_static_branches(elem->aux->prog, map, on);
		if (err)
			break;
	}

unlock_ret:
	mutex_unlock(&map->static_key_mutex);
	return err;
}

static bool init_static_jump_instruction(struct bpf_prog *prog,
					 struct bpf_static_branch *branch,
					 struct bpf_static_branch_info *branch_info)
{
	bool inverse = !!(branch_info->flags & BPF_F_INVERSE_BRANCH);
	u32 insn_offset = branch_info->insn_offset;
	u32 jump_target = branch_info->jump_target;
	struct bpf_insn *jump_insn;
	s32 jump_offset;

	if (insn_offset % 8 || jump_target % 8)
		return false;

	if (insn_offset / 8 >= prog->len || jump_target / 8 >= prog->len)
		return false;

	jump_insn = &prog->insnsi[insn_offset / 8];
	if (jump_insn->code != (BPF_JMP | BPF_JA) &&
	    jump_insn->code != (BPF_JMP32 | BPF_JA))
		return false;

	if (jump_insn->dst_reg || jump_insn->src_reg)
		return false;

	if (jump_insn->off && jump_insn->imm)
		return false;

	jump_offset = ((long)jump_target - (long)insn_offset) / 8 - 1;

	if (inverse) {
		if (jump_insn->code == (BPF_JMP | BPF_JA)) {
			if (jump_insn->off != jump_offset)
				return false;
		} else {
			if (jump_insn->imm != jump_offset)
				return false;
		}
	} else {
		/* The instruction here should be JA 0. We will replace it by a
		 * non-zero jump so that this is simpler to verify this program
		 * (verifier might optimize out such instructions and we don't
		 * want to care about this). After verification the instruction
		 * will be set to proper value
		 */
		if (jump_insn->off || jump_insn->imm)
			return false;

		if (jump_insn->code == (BPF_JMP | BPF_JA))
			jump_insn->off = jump_offset;
		else
			jump_insn->imm = jump_offset;
	}

	memcpy(branch->bpf_jmp, jump_insn, 8);
	branch->bpf_offset = insn_offset;
	return true;
}

static int
__bpf_prog_init_static_branches(struct bpf_prog *prog,
				struct bpf_static_branch_info *static_branches_info,
				int n)
{
	size_t size = n * sizeof(*prog->aux->static_branches);
	struct bpf_static_branch *static_branches;
	struct bpf_map *map;
	int i, err = 0;

	static_branches = kzalloc(size, GFP_USER | __GFP_NOWARN);
	if (!static_branches)
		return -ENOMEM;

	for (i = 0; i < n; i++) {
		if (static_branches_info[i].flags & ~(BPF_F_INVERSE_BRANCH)) {
			err = -EINVAL;
			goto free_static_branches;
		}
		static_branches[i].flags = static_branches_info[i].flags;

		if (!init_static_jump_instruction(prog, &static_branches[i],
						  &static_branches_info[i])) {
			err = -EINVAL;
			goto free_static_branches;
		}

		map = bpf_map_get(static_branches_info[i].map_fd);
		if (IS_ERR(map)) {
			err = PTR_ERR(map);
			goto free_static_branches;
		}

		if (!(map->map_flags & BPF_F_STATIC_KEY)) {
			bpf_map_put(map);
			err = -EINVAL;
			goto free_static_branches;
		}

		err = __bpf_prog_bind_map(prog, map, true);
		if (err) {
			bpf_map_put(map);
			if (err != -EEXIST)
				goto free_static_branches;
		}

		static_branches[i].map = map;
	}

	prog->aux->static_branches = static_branches;
	prog->aux->static_branches_len = n;

	return 0;

free_static_branches:
	kfree(static_branches);
	return err;
}

int bpf_prog_init_static_branches(struct bpf_prog *prog, union bpf_attr *attr)
{
	void __user *user_static_branches = u64_to_user_ptr(attr->static_branches_info);
	size_t item_size = sizeof(struct bpf_static_branch_info);
	struct bpf_static_branch_info *static_branches_info;
	size_t size = attr->static_branches_info_size;
	int err = 0;

	if (!attr->static_branches_info)
		return size ? -EINVAL : 0;
	if (!size)
		return -EINVAL;
	if (size % item_size)
		return -EINVAL;

	if (!bpf_jit_supports_static_keys())
		return -EOPNOTSUPP;

	static_branches_info = kzalloc(size, GFP_USER | __GFP_NOWARN);
	if (!static_branches_info)
		return -ENOMEM;

	if (copy_from_user(static_branches_info, user_static_branches, size)) {
		err = -EFAULT;
		goto free_branches;
	}

	err = __bpf_prog_init_static_branches(prog, static_branches_info,
					      size / item_size);
	if (err)
		goto free_branches;

	err = 0;

free_branches:
	kfree(static_branches_info);
	return err;
}

int bpf_prog_register_static_branches(struct bpf_prog *prog)
{
	int n_branches = prog->aux->static_branches_len;
	struct bpf_static_branch *branch;
	int err;
	u32 i;

	for (i = 0; i < n_branches; i++) {
		branch = &prog->aux->static_branches[i];

		/* JIT compiler did not detect this branch
		 * and thus won't be able to poke it when asked to
		 */
		if (!branch->arch_len)
			return -EINVAL;
	}

	for (i = 0; i < n_branches; i++) {
		branch = &prog->aux->static_branches[i];
		err = static_key_add_prog(branch->map, prog);
		if (err)
			break;
	}

	return 0;
}
