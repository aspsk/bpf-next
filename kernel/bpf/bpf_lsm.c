// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/seq_file.h>
#include <linux/bpf_lsm.h>
#include <linux/kallsyms.h>
#include <net/bpf_sk_storage.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf_ids.h>
#include <linux/ima.h>
#include <linux/bpf-cgroup.h>
#include <linux/sort.h>

/* For every LSM hook that allows attachment of BPF programs, declare a nop
 * function where a BPF program can be attached. Notably, we qualify each with
 * weak linkage such that strong overrides can be implemented if need be.
 */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
__weak noinline RET bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#include <linux/bpf_lsm_hook_defs.h>
#undef LSM_HOOK

#define LSM_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
BTF_SET_START(bpf_lsm_hooks)
#include <linux/lsm_hook_defs.h>
#include <linux/bpf_lsm_hook_defs.h>
#undef LSM_HOOK
BTF_SET_END(bpf_lsm_hooks)

BTF_ID_LIST(bpf_lsm_bpf_only_hooks)
#define LSM_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
#include <linux/bpf_lsm_hook_defs.h>
#undef LSM_HOOK

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	DEFINE_STATIC_KEY_FALSE(BPF_HOOK_KEY_NAME(NAME));
#include <linux/bpf_lsm_hook_defs.h>
#undef LSM_HOOK

struct bpf_lsm_hook_key {
	u32 btf_id;
	struct static_key_false *key;
};

static struct bpf_lsm_hook_key hook_keys[] __ro_after_init = {
#define LSM_HOOK(RET, DEFAULT, NAME, ...) { .key = &BPF_HOOK_KEY_NAME(NAME) },
#include <linux/bpf_lsm_hook_defs.h>
#undef LSM_HOOK
};

static int __init bpf_lsm_hook_keys_init(void)
{
	int i, n = ARRAY_SIZE(hook_keys);

	for (i = 0; i < n; i++)
		hook_keys[i].btf_id = bpf_lsm_bpf_only_hooks[i];

	sort(hook_keys, n, sizeof(hook_keys[0]), btf_id_cmp_func, NULL);

	return 0;
}
core_initcall(bpf_lsm_hook_keys_init);

static struct static_key_false *bpf_lsm_btf_id_to_key(u32 btf_id)
{
	const struct bpf_lsm_hook_key *hook;

	if (!btf_id)
		return NULL;

	hook = bsearch(&btf_id, hook_keys, ARRAY_SIZE(hook_keys),
		       sizeof(hook_keys[0]), btf_id_cmp_func);
	if (hook)
		return hook->key;

	return NULL;
}

static struct static_key_false *bpf_lsm_prog_to_key(const struct bpf_prog *prog)
{
	if (prog->type != BPF_PROG_TYPE_LSM ||
	    prog->expected_attach_type != BPF_LSM_MAC)
		return NULL;

	return bpf_lsm_btf_id_to_key(prog->aux->attach_btf_id);
}

void bpf_lsm_hook_inc(const struct bpf_prog *prog)
{
	struct static_key_false *key = bpf_lsm_prog_to_key(prog);

	if (key)
		static_branch_inc(key);
}

void bpf_lsm_hook_dec(const struct bpf_prog *prog)
{
	struct static_key_false *key = bpf_lsm_prog_to_key(prog);

	if (key)
		static_branch_dec(key);
}

BTF_SET_START(bpf_lsm_disabled_hooks)
BTF_ID(func, bpf_lsm_vm_enough_memory)
BTF_ID(func, bpf_lsm_inode_need_killpriv)
BTF_ID(func, bpf_lsm_inode_getsecurity)
BTF_ID(func, bpf_lsm_inode_listsecurity)
BTF_ID(func, bpf_lsm_inode_copy_up_xattr)
BTF_ID(func, bpf_lsm_getselfattr)
BTF_ID(func, bpf_lsm_getprocattr)
BTF_ID(func, bpf_lsm_setprocattr)
#ifdef CONFIG_KEYS
BTF_ID(func, bpf_lsm_key_getsecurity)
#endif
#ifdef CONFIG_AUDIT
BTF_ID(func, bpf_lsm_audit_rule_match)
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
BTF_ID(func, bpf_lsm_xfrm_decode_session)
#endif
BTF_ID(func, bpf_lsm_ismaclabel)
BTF_ID(func, bpf_lsm_file_alloc_security)
BTF_SET_END(bpf_lsm_disabled_hooks)

/* List of LSM hooks that should operate on 'current' cgroup regardless
 * of function signature.
 */
BTF_SET_START(bpf_lsm_current_hooks)
/* operate on freshly allocated sk without any cgroup association */
#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_sk_alloc_security)
BTF_ID(func, bpf_lsm_sk_free_security)
#endif
BTF_SET_END(bpf_lsm_current_hooks)

/* List of LSM hooks that trigger while the socket is properly locked.
 */
BTF_SET_START(bpf_lsm_locked_sockopt_hooks)
#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_sock_graft)
BTF_ID(func, bpf_lsm_inet_csk_clone)
BTF_ID(func, bpf_lsm_inet_conn_established)
#endif
BTF_SET_END(bpf_lsm_locked_sockopt_hooks)

/* List of LSM hooks that trigger while the socket is _not_ locked,
 * but it's ok to call bpf_{g,s}etsockopt because the socket is still
 * in the early init phase.
 */
BTF_SET_START(bpf_lsm_unlocked_sockopt_hooks)
#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_socket_post_create)
BTF_ID(func, bpf_lsm_socket_socketpair)
#endif
BTF_SET_END(bpf_lsm_unlocked_sockopt_hooks)

#ifdef CONFIG_CGROUP_BPF
void bpf_lsm_find_cgroup_shim(const struct bpf_prog *prog,
			     bpf_func_t *bpf_func)
{
	const struct btf_param *args __maybe_unused;

	if (btf_type_vlen(prog->aux->attach_func_proto) < 1 ||
	    btf_id_set_contains(&bpf_lsm_current_hooks,
				prog->aux->attach_btf_id)) {
		*bpf_func = __cgroup_bpf_run_lsm_current;
		return;
	}

#ifdef CONFIG_NET
	args = btf_params(prog->aux->attach_func_proto);

	if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCKET])
		*bpf_func = __cgroup_bpf_run_lsm_socket;
	else if (args[0].type == btf_sock_ids[BTF_SOCK_TYPE_SOCK])
		*bpf_func = __cgroup_bpf_run_lsm_sock;
	else
#endif
		*bpf_func = __cgroup_bpf_run_lsm_current;
}
#endif

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog)
{
	u32 btf_id = prog->aux->attach_btf_id;
	const char *func_name = prog->aux->attach_func_name;

	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (btf_id_set_contains(&bpf_lsm_disabled_hooks, btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to disabled hook %s\n",
			btf_id, func_name);
		return -EINVAL;
	}

	if (!btf_id_set_contains(&bpf_lsm_hooks, btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			btf_id, func_name);
		return -EINVAL;
	}

	return 0;
}

/* Mask for all the currently supported BPRM option flags */
#define BPF_F_BRPM_OPTS_MASK	BPF_F_BPRM_SECUREEXEC

BPF_CALL_2(bpf_bprm_opts_set, struct linux_binprm *, bprm, u64, flags)
{
	if (flags & ~BPF_F_BRPM_OPTS_MASK)
		return -EINVAL;

	bprm->secureexec = (flags & BPF_F_BPRM_SECUREEXEC);
	return 0;
}

BTF_ID_LIST_SINGLE(bpf_bprm_opts_set_btf_ids, struct, linux_binprm)

static const struct bpf_func_proto bpf_bprm_opts_set_proto = {
	.func		= bpf_bprm_opts_set,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_bprm_opts_set_btf_ids[0],
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_ima_inode_hash, struct inode *, inode, void *, dst, u32, size)
{
	return ima_inode_hash(inode, dst, size);
}

static bool bpf_ima_inode_hash_allowed(const struct bpf_prog *prog)
{
	return bpf_lsm_is_sleepable_hook(prog->aux->attach_btf_id);
}

BTF_ID_LIST_SINGLE(bpf_ima_inode_hash_btf_ids, struct, inode)

static const struct bpf_func_proto bpf_ima_inode_hash_proto = {
	.func		= bpf_ima_inode_hash,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_inode_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_MEM_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

BPF_CALL_3(bpf_ima_file_hash, struct file *, file, void *, dst, u32, size)
{
	return ima_file_hash(file, dst, size);
}

BTF_ID_LIST_SINGLE(bpf_ima_file_hash_btf_ids, struct, file)

static const struct bpf_func_proto bpf_ima_file_hash_proto = {
	.func		= bpf_ima_file_hash,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_file_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_MEM_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

BPF_CALL_1(bpf_get_attach_cookie, void *, ctx)
{
	struct bpf_trace_run_ctx *run_ctx;

	run_ctx = container_of(current->bpf_ctx, struct bpf_trace_run_ctx, run_ctx);
	return run_ctx->bpf_cookie;
}

static const struct bpf_func_proto bpf_get_attach_cookie_proto = {
	.func		= bpf_get_attach_cookie,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

static const struct bpf_func_proto *
bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	const struct bpf_func_proto *func_proto;

	if (prog->expected_attach_type == BPF_LSM_CGROUP) {
		func_proto = cgroup_common_func_proto(func_id, prog);
		if (func_proto)
			return func_proto;
	}

	switch (func_id) {
	case BPF_FUNC_inode_storage_get:
		return &bpf_inode_storage_get_proto;
	case BPF_FUNC_inode_storage_delete:
		return &bpf_inode_storage_delete_proto;
#ifdef CONFIG_NET
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
#endif /* CONFIG_NET */
	case BPF_FUNC_spin_lock:
		return &bpf_spin_lock_proto;
	case BPF_FUNC_spin_unlock:
		return &bpf_spin_unlock_proto;
	case BPF_FUNC_bprm_opts_set:
		return &bpf_bprm_opts_set_proto;
	case BPF_FUNC_ima_inode_hash:
		return &bpf_ima_inode_hash_proto;
	case BPF_FUNC_ima_file_hash:
		return &bpf_ima_file_hash_proto;
	case BPF_FUNC_get_attach_cookie:
		return bpf_prog_has_trampoline(prog) ? &bpf_get_attach_cookie_proto : NULL;
#ifdef CONFIG_NET
	case BPF_FUNC_setsockopt:
		if (prog->expected_attach_type != BPF_LSM_CGROUP)
			return NULL;
		if (btf_id_set_contains(&bpf_lsm_locked_sockopt_hooks,
					prog->aux->attach_btf_id))
			return &bpf_sk_setsockopt_proto;
		if (btf_id_set_contains(&bpf_lsm_unlocked_sockopt_hooks,
					prog->aux->attach_btf_id))
			return &bpf_unlocked_sk_setsockopt_proto;
		return NULL;
	case BPF_FUNC_getsockopt:
		if (prog->expected_attach_type != BPF_LSM_CGROUP)
			return NULL;
		if (btf_id_set_contains(&bpf_lsm_locked_sockopt_hooks,
					prog->aux->attach_btf_id))
			return &bpf_sk_getsockopt_proto;
		if (btf_id_set_contains(&bpf_lsm_unlocked_sockopt_hooks,
					prog->aux->attach_btf_id))
			return &bpf_unlocked_sk_getsockopt_proto;
		return NULL;
#endif
	default:
		return tracing_prog_func_proto(func_id, prog);
	}
}

/* The set of hooks which are called without pagefaults disabled and are allowed
 * to "sleep" and thus can be used for sleepable BPF programs.
 */
BTF_SET_START(sleepable_lsm_hooks)
BTF_ID(func, bpf_lsm_bpf)
BTF_ID(func, bpf_lsm_bpf_map)
BTF_ID(func, bpf_lsm_bpf_map_create)
BTF_ID(func, bpf_lsm_bpf_map_free)
BTF_ID(func, bpf_lsm_bpf_prog)
BTF_ID(func, bpf_lsm_bpf_prog_load)
BTF_ID(func, bpf_lsm_bpf_token_create)
BTF_ID(func, bpf_lsm_bpf_token_free)
BTF_ID(func, bpf_lsm_bpf_token_cmd)
BTF_ID(func, bpf_lsm_bpf_token_capable)
BTF_ID(func, bpf_lsm_bprm_check_security)
BTF_ID(func, bpf_lsm_bprm_committed_creds)
BTF_ID(func, bpf_lsm_bprm_committing_creds)
BTF_ID(func, bpf_lsm_bprm_creds_for_exec)
BTF_ID(func, bpf_lsm_bprm_creds_from_file)
BTF_ID(func, bpf_lsm_capget)
BTF_ID(func, bpf_lsm_capset)
BTF_ID(func, bpf_lsm_cred_prepare)
BTF_ID(func, bpf_lsm_file_ioctl)
BTF_ID(func, bpf_lsm_file_lock)
BTF_ID(func, bpf_lsm_file_open)
BTF_ID(func, bpf_lsm_file_post_open)
BTF_ID(func, bpf_lsm_file_receive)

BTF_ID(func, bpf_lsm_inode_create)
BTF_ID(func, bpf_lsm_inode_free_security)
BTF_ID(func, bpf_lsm_inode_getattr)
BTF_ID(func, bpf_lsm_inode_getxattr)
BTF_ID(func, bpf_lsm_inode_mknod)
BTF_ID(func, bpf_lsm_inode_need_killpriv)
BTF_ID(func, bpf_lsm_inode_post_setxattr)
BTF_ID(func, bpf_lsm_inode_post_removexattr)
BTF_ID(func, bpf_lsm_inode_readlink)
BTF_ID(func, bpf_lsm_inode_removexattr)
BTF_ID(func, bpf_lsm_inode_rename)
BTF_ID(func, bpf_lsm_inode_rmdir)
BTF_ID(func, bpf_lsm_inode_setattr)
BTF_ID(func, bpf_lsm_inode_setxattr)
BTF_ID(func, bpf_lsm_inode_symlink)
BTF_ID(func, bpf_lsm_inode_unlink)
BTF_ID(func, bpf_lsm_kernel_module_request)
BTF_ID(func, bpf_lsm_kernel_read_file)
BTF_ID(func, bpf_lsm_kernfs_init_security)

#ifdef CONFIG_SECURITY_PATH
BTF_ID(func, bpf_lsm_path_unlink)
BTF_ID(func, bpf_lsm_path_mkdir)
BTF_ID(func, bpf_lsm_path_rmdir)
BTF_ID(func, bpf_lsm_path_truncate)
BTF_ID(func, bpf_lsm_path_symlink)
BTF_ID(func, bpf_lsm_path_link)
BTF_ID(func, bpf_lsm_path_rename)
BTF_ID(func, bpf_lsm_path_chmod)
BTF_ID(func, bpf_lsm_path_chown)
#endif /* CONFIG_SECURITY_PATH */

BTF_ID(func, bpf_lsm_mmap_file)
BTF_ID(func, bpf_lsm_netlink_send)
BTF_ID(func, bpf_lsm_path_notify)
BTF_ID(func, bpf_lsm_release_secctx)
BTF_ID(func, bpf_lsm_sb_alloc_security)
BTF_ID(func, bpf_lsm_sb_eat_lsm_opts)
BTF_ID(func, bpf_lsm_sb_kern_mount)
BTF_ID(func, bpf_lsm_sb_mount)
BTF_ID(func, bpf_lsm_sb_remount)
BTF_ID(func, bpf_lsm_sb_set_mnt_opts)
BTF_ID(func, bpf_lsm_sb_show_options)
BTF_ID(func, bpf_lsm_sb_statfs)
BTF_ID(func, bpf_lsm_sb_umount)
BTF_ID(func, bpf_lsm_settime)

#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_socket_accept)
BTF_ID(func, bpf_lsm_socket_bind)
BTF_ID(func, bpf_lsm_socket_connect)
BTF_ID(func, bpf_lsm_socket_create)
BTF_ID(func, bpf_lsm_socket_getpeername)
BTF_ID(func, bpf_lsm_socket_getpeersec_dgram)
BTF_ID(func, bpf_lsm_socket_getsockname)
BTF_ID(func, bpf_lsm_socket_getsockopt)
BTF_ID(func, bpf_lsm_socket_listen)
BTF_ID(func, bpf_lsm_socket_post_create)
BTF_ID(func, bpf_lsm_socket_recvmsg)
BTF_ID(func, bpf_lsm_socket_sendmsg)
BTF_ID(func, bpf_lsm_socket_shutdown)
BTF_ID(func, bpf_lsm_socket_socketpair)
#endif /* CONFIG_SECURITY_NETWORK */

BTF_ID(func, bpf_lsm_syslog)
BTF_ID(func, bpf_lsm_task_alloc)
BTF_ID(func, bpf_lsm_task_prctl)
BTF_ID(func, bpf_lsm_task_setscheduler)
BTF_ID(func, bpf_lsm_userns_create)
BTF_ID(func, bpf_lsm_bdev_alloc_security)
BTF_ID(func, bpf_lsm_bdev_setintegrity)
BTF_SET_END(sleepable_lsm_hooks)

BTF_SET_START(untrusted_lsm_hooks)
BTF_ID(func, bpf_lsm_bpf_map_free)
BTF_ID(func, bpf_lsm_bpf_prog_free)
BTF_ID(func, bpf_lsm_file_alloc_security)
BTF_ID(func, bpf_lsm_file_free_security)
#ifdef CONFIG_SECURITY_NETWORK
BTF_ID(func, bpf_lsm_sk_alloc_security)
BTF_ID(func, bpf_lsm_sk_free_security)
#endif /* CONFIG_SECURITY_NETWORK */
BTF_ID(func, bpf_lsm_task_free)
BTF_ID(func, bpf_lsm_bdev_alloc_security)
BTF_ID(func, bpf_lsm_bdev_free_security)
BTF_SET_END(untrusted_lsm_hooks)

bool bpf_lsm_is_sleepable_hook(u32 btf_id)
{
	return btf_id_set_contains(&sleepable_lsm_hooks, btf_id);
}

bool bpf_lsm_is_trusted(const struct bpf_prog *prog)
{
	return !btf_id_set_contains(&untrusted_lsm_hooks, prog->aux->attach_btf_id);
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_lsm_func_proto,
	.is_valid_access = btf_ctx_access,
};

/* hooks return 0 or 1 */
BTF_SET_START(bool_lsm_hooks)
#ifdef CONFIG_SECURITY_NETWORK_XFRM
BTF_ID(func, bpf_lsm_xfrm_state_pol_flow_match)
#endif
#ifdef CONFIG_AUDIT
BTF_ID(func, bpf_lsm_audit_rule_known)
#endif
BTF_ID(func, bpf_lsm_inode_xattr_skipcap)
BTF_SET_END(bool_lsm_hooks)

/* hooks returning void */
#define LSM_HOOK_void(DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
#define LSM_HOOK_int(DEFAULT, NAME, ...)  /* nothing */
#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_##RET(DEFAULT, NAME, __VA_ARGS__)
BTF_SET_START(void_lsm_hooks)
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK
#undef LSM_HOOK_void
#undef LSM_HOOK_int
BTF_SET_END(void_lsm_hooks)

bool bpf_lsm_hook_returns_errno(u32 btf_id)
{
	if (btf_id_set_contains(&bool_lsm_hooks, btf_id))
		return false;
	if (btf_id_set_contains(&void_lsm_hooks, btf_id))
		return false;
	return true;
}

int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
			     struct bpf_retval_range *retval_range)
{
	/* no return value range for void hooks */
	if (!prog->aux->attach_func_proto->type)
		return -EINVAL;

	if (btf_id_set_contains(&bool_lsm_hooks, prog->aux->attach_btf_id)) {
		retval_range->minval = 0;
		retval_range->maxval = 1;
	} else {
		/* All other available LSM hooks, except task_prctl, return 0
		 * on success and negative error code on failure.
		 * To keep things simple, we only allow bpf progs to return 0
		 * or negative errno for task_prctl too.
		 */
		retval_range->minval = -MAX_ERRNO;
		retval_range->maxval = 0;
	}
	return 0;
}

enum bpf_lsm_info_flags {
	BPF_LSM_INFO_F_DISABLED  = BIT(0),
	BPF_LSM_INFO_F_BPF_ONLY  = BIT(1),
	BPF_LSM_INFO_F_SLEEPABLE = BIT(2),
};

struct bpf_lsm_info {
	u32 btf_id;
	u32 flags;
};

static void bpf_lsm_fill_info(struct bpf_lsm_info *info, u32 btf_id)
{
	bool bpf_only = !!bpf_lsm_btf_id_to_key(btf_id); /* list, not set */
	bool disabled = btf_id_set_contains(&bpf_lsm_disabled_hooks, btf_id);
	bool sleepable = btf_id_set_contains(&sleepable_lsm_hooks, btf_id);

	info->btf_id = btf_id;
	info->flags = 0;

	if (disabled)
		info->flags |= BPF_LSM_INFO_F_DISABLED;
	if (bpf_only)
		info->flags |= BPF_LSM_INFO_F_BPF_ONLY;
	if (sleepable)
		info->flags |= BPF_LSM_INFO_F_SLEEPABLE;
}

static void *bpf_lsm_get_info(struct seq_file *seq, loff_t pos)
{
	struct bpf_lsm_info *info = seq->private;

	if (pos < 0 || (u64)pos >= bpf_lsm_hooks.cnt)
		return NULL;

	bpf_lsm_fill_info(info, bpf_lsm_hooks.ids[pos]);

	return info;
}

static void *bpf_lsm_seq_start(struct seq_file *seq, loff_t *pos)
{
	return bpf_lsm_get_info(seq, *pos);
}

static void *bpf_lsm_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return bpf_lsm_get_info(seq, ++*pos);
}

struct bpf_iter__bpf_lsm {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct bpf_lsm_info *, lsm_info);
};

DEFINE_BPF_ITER_FUNC(bpf_lsm, struct bpf_iter_meta *meta, struct bpf_lsm_info *lsm_info)

static int __bpf_lsm_seq_show(struct seq_file *seq, void *v, bool in_stop)
{
	struct bpf_iter__bpf_lsm ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;
	int ret = 0;

	ctx.meta = &meta;
	ctx.lsm_info = v;
	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (prog)
		ret = bpf_iter_run_prog(prog, &ctx);

	return ret;
}

static int bpf_lsm_seq_show(struct seq_file *seq, void *v)
{
	return __bpf_lsm_seq_show(seq, v, false);
}

static void bpf_lsm_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void) __bpf_lsm_seq_show(seq, NULL, true);
}

static const struct seq_operations bpf_lsm_seq_ops = {
	.start	= bpf_lsm_seq_start,
	.next	= bpf_lsm_seq_next,
	.stop	= bpf_lsm_seq_stop,
	.show	= bpf_lsm_seq_show,
};

BTF_ID_LIST_SINGLE(btf_bpf_lsm_info_id, struct, bpf_lsm_info)

static const struct bpf_iter_seq_info bpf_lsm_seq_info = {
	.seq_ops		= &bpf_lsm_seq_ops,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= sizeof(struct bpf_lsm_info),
};

static struct bpf_iter_reg bpf_lsm_reg_info = {
	.target			= "bpf_lsm",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__bpf_lsm, lsm_info), PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &bpf_lsm_seq_info,
};

static int __init bpf_lsm_iter_init(void)
{
	bpf_lsm_reg_info.ctx_arg_info[0].btf_id = *btf_bpf_lsm_info_id;
	return bpf_iter_reg_target(&bpf_lsm_reg_info);
}

late_initcall(bpf_lsm_iter_init);
