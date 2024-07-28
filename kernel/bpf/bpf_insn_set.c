// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Isovalent
 */

// XXX: cleanup the list of includes
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <uapi/linux/btf.h>
#include <linux/rcupdate_trace.h>
#include <linux/btf_ids.h>

#define MAX_ISET_ENTRIES 64

struct insn_ptr {
	u32 xlated_off;

	struct {
		void *jitted_ip;
		u32 jitted_off;
		u32 jitted_len;
		u32 jitted_jump_offset;
	};
};

struct bpf_insn_set {
	struct bpf_map map;
	DECLARE_FLEX_ARRAY(struct insn_ptr, ptrs);
};

static inline u32 insn_set_map_alloc_size(u32 max_entries)
{
	return sizeof(struct bpf_insn_set) + sizeof(struct insn_ptr) * max_entries;
}

static int insn_set_map_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries == 0 ||
	    attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags != 0)
		return -EINVAL;

	if (attr->max_entries > MAX_ISET_ENTRIES)
		return -E2BIG;

	return 0;
}

static struct bpf_map *insn_set_map_alloc(union bpf_attr *attr)
{
	u64 size = insn_set_map_alloc_size(attr->max_entries);
	struct bpf_insn_set *insn_set;

	insn_set = bpf_map_area_alloc(size, NUMA_NO_NODE);
	if (!insn_set)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&insn_set->map, attr);

	return &insn_set->map;
}

static int insn_set_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_insn_set *insn_set = container_of(map, struct bpf_insn_set, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= insn_set->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == insn_set->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

static void *insn_set_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_insn_set *insn_set = container_of(map, struct bpf_insn_set, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= insn_set->map.max_entries))
		return NULL;

	return &insn_set->ptrs[index].xlated_off;
}

static long insn_set_map_update_elem(struct bpf_map *map, void *key, void *value, u64 map_flags)
{
	struct bpf_insn_set *insn_set = container_of(map, struct bpf_insn_set, map);
	u32 index = *(u32 *)key;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		return -EINVAL;

	if (unlikely(index >= insn_set->map.max_entries))
		return -E2BIG;

	if (unlikely(map_flags & BPF_NOEXIST))
		return -EEXIST;

	copy_map_value(map, &insn_set->ptrs[index].xlated_off, value);

	return 0;
}

static long insn_set_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

static int insn_set_map_check_btf(const struct bpf_map *map, const struct btf *btf, const struct btf_type *key_type, const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	if (BTF_INFO_KIND(value_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	int_data = *(u32 *)(value_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

static void insn_set_map_free(struct bpf_map *map)
{
	struct bpf_insn_set *insn_set = container_of(map, struct bpf_insn_set, map);

	bpf_map_area_free(insn_set);
}

static bool insn_set_map_meta_equal(const struct bpf_map *meta0, const struct bpf_map *meta1)
{
	if (!bpf_map_meta_equal(meta0, meta1))
		return false;
	return meta0->map_flags & BPF_F_INNER_MAP ? true :
	       meta0->max_entries == meta1->max_entries;
}

static u64 insn_set_map_mem_usage(const struct bpf_map *map)
{
	return insn_set_map_alloc_size(map->max_entries);
}

/*
 * XXX how to dump the array (it's supposed to be read-only)?
 */
BTF_ID_LIST_SINGLE(insn_set_map_btf_ids, struct, bpf_insn_set)
const struct bpf_map_ops insn_set_map_ops = {
	.map_meta_equal = insn_set_map_meta_equal,
	.map_alloc_check = insn_set_map_alloc_check,
	.map_alloc = insn_set_map_alloc,
	.map_free = insn_set_map_free,
	.map_get_next_key = insn_set_map_get_next_key,
	.map_lookup_elem = insn_set_map_lookup_elem,
	.map_update_elem = insn_set_map_update_elem,
	.map_delete_elem = insn_set_map_delete_elem,
	.map_check_btf = insn_set_map_check_btf,
	.map_mem_usage = insn_set_map_mem_usage,
	.map_btf_id = &insn_set_map_btf_ids[0],
};

void insn_set_map_adjust(struct bpf_map *map, u32 off, u32 len)
{
	struct bpf_insn_set *insn_set = container_of(map, struct bpf_insn_set, map);
	u32 diff;
	int i;

	diff = len - 1;
	if (!diff)
		return;

	for (i = 0; i < map->max_entries; i++) {
		if (insn_set->ptrs[i].xlated_off <= off)
			continue;
		insn_set->ptrs[i].xlated_off += diff;
	}
}

// XXX really stupid brute force implementation
// XXX is verifier env still alive by this point?
static struct insn_ptr *insn_ptr_by_offset(struct bpf_prog *prog, u32 xlated_off)
{
	struct bpf_insn_set *insn_set;
	struct bpf_map *map;
	int i, j;

	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		map = prog->aux->used_maps[i];
		if (map->map_type != BPF_MAP_TYPE_INSN_SET)
			continue;
/*
 XXX
		if (!(map->map_flags & BPF_F_STATIC_KEY))
			continue;
*/

		insn_set = container_of(map, struct bpf_insn_set, map);
		for (j = 0; j < map->max_entries; j++) {
			if (insn_set->ptrs[j].xlated_off == xlated_off) // XXX subprogs? :hmm:
				return &insn_set->ptrs[j];
		}
	}

	// XXX when adding a map we need to check that only unique offsets are present

	return NULL;
}

void bpf_prog_update_jitted_insn_offset(struct bpf_prog *prog, u32 xlated_off, u32 jitted_off, u32 jitted_len, u32 jitted_jump_offset, void *jitted_ip)
{
	struct insn_ptr *ptr;

	ptr = insn_ptr_by_offset(prog, xlated_off);
	if (ptr) {
		ptr->jitted_ip = jitted_ip;
		ptr->jitted_off = jitted_off;
		ptr->jitted_len = jitted_len;
		ptr->jitted_jump_offset = jitted_jump_offset;
	}
}
