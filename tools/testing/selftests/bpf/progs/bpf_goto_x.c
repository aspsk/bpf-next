// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__u64 ret_user;

struct simple_ctx {
	__u64 x;
};

__noinline int __simple_test(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

SEC("syscall") int simple_test(struct simple_ctx *ctx)
{
	ret_user = 0;
	return __simple_test(ctx);
}

SEC("syscall")
int two_towers(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	switch (ctx->x + !!ret_user) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 102;
		break;
	case 1:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 103;
		break;
	case 2:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 104;
		break;
	case 3:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 107;
		break;
	case 4:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 205;
		break;
	case 5:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 115;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 1019;
		break;
	}


	return 0;
}

SEC("syscall")
int the_return_of_the_king(struct simple_ctx *ctx)
{
	switch (ctx->x) {
	case 0:
		bpf_printk("%lu\n", ctx->x + 1);
		ret_user = 2;
		break;
	case 11:
		bpf_printk("%lu\n", ctx->x + 7);
		ret_user = 3;
		break;
	case 27:
		bpf_printk("%lu\n", ctx->x + 9);
		ret_user = 4;
		break;
	case 31:
		bpf_printk("%lu\n", ctx->x + 11);
		ret_user = 5;
		break;
	case 447:
		bpf_printk("%lu\n", ctx->x + 17);
		ret_user = 7;
		break;
	default:
		bpf_printk("%lu\n", ctx->x + 177);
		ret_user = 19;
		break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
