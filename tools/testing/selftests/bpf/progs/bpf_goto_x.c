// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

__u64 in_user;
__u64 ret_user;

struct simple_ctx {
	__u64 x;
};

__u64 some_var;

/*
 * This function adds code which will be replaced by a different
 * number of instructions by the verifier. This adds additional
 * stress on testing the insn_array maps corresponding to indirect jumps.
 */
static __always_inline void adjust_insns(__u64 x)
{
	some_var ^= x + bpf_jiffies64();
}

SEC("syscall")
int simple_test(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(ctx->x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int simple_test2(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(ctx->x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int simple_test_other_sec(struct pt_regs *ctx)
{
	__u64 x = in_user;

	switch (x) {
	case 0:
		adjust_insns(x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int two_switches(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(ctx->x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret_user = 19;
		break;
	}

	switch (ctx->x + !!ret_user) {
	case 1:
		adjust_insns(ctx->x + 7);
		ret_user = 103;
		break;
	case 2:
		adjust_insns(ctx->x + 9);
		ret_user = 104;
		break;
	case 3:
		adjust_insns(ctx->x + 11);
		ret_user = 107;
		break;
	case 4:
		adjust_insns(ctx->x + 11);
		ret_user = 205;
		break;
	case 5:
		adjust_insns(ctx->x + 11);
		ret_user = 115;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret_user = 1019;
		break;
	}

	return 0;
}

SEC("syscall")
int big_jump_table(struct simple_ctx *ctx)
{
	/*
	 * LLVM will create a JT of size 32, and consider 447
	 * and 'default' as special cases
	 */
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 1);
		ret_user = 2;
		break;
	case 11:
		adjust_insns(ctx->x + 7);
		ret_user = 3;
		break;
	case 27:
		adjust_insns(ctx->x + 9);
		ret_user = 4;
		break;
	case 31:
		adjust_insns(ctx->x + 11);
		ret_user = 5;
		break;
	case 447:
		adjust_insns(ctx->x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

/* Just to introduce some non-zero offsets in .text */
static __noinline int f0(volatile struct simple_ctx *ctx __arg_ctx)
{
	if (ctx)
		return 1;
	else
		return 13;
}

SEC("syscall") int f1(struct simple_ctx *ctx)
{
	ret_user = 0;
	return f0(ctx);
}

static __noinline int __static_global(__u64 x)
{
	switch (x) {
	case 0:
		adjust_insns(x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int use_static_global1(struct simple_ctx *ctx)
{
	ret_user = 0;
	return __static_global(ctx->x);
}

SEC("syscall")
int use_static_global2(struct simple_ctx *ctx)
{
	ret_user = 0;
	adjust_insns(ctx->x + 1);
	return __static_global(ctx->x);
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int use_static_global_other_sec(void *ctx)
{
	return __static_global(in_user);
}

__noinline int __nonstatic_global(__u64 x)
{
	switch (x) {
	case 0:
		adjust_insns(x + 1);
		ret_user = 2;
		break;
	case 1:
		adjust_insns(x + 7);
		ret_user = 3;
		break;
	case 2:
		adjust_insns(x + 9);
		ret_user = 4;
		break;
	case 3:
		adjust_insns(x + 11);
		ret_user = 5;
		break;
	case 4:
		adjust_insns(x + 17);
		ret_user = 7;
		break;
	default:
		adjust_insns(x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall")
int use_nonstatic_global1(struct simple_ctx *ctx)
{
	ret_user = 0;
	return __nonstatic_global(ctx->x);
}

SEC("syscall")
int use_nonstatic_global2(struct simple_ctx *ctx)
{
	ret_user = 0;
	adjust_insns(ctx->x + 1);
	return __nonstatic_global(ctx->x);
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int use_nonstatic_global_other_sec(void *ctx)
{
	return __nonstatic_global(in_user);
}

char _license[] SEC("license") = "GPL";
