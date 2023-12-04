// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

DEFINE_STATIC_KEY(key1);
DEFINE_STATIC_KEY(key2);
DEFINE_STATIC_KEY(key3);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} just_map SEC(".maps");

int ret_user;

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key(void *ctx)
{
	if (bpf_static_branch_likely(&key1))
		ret_user += 3;
	else
		ret_user += 4;

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_another_prog(void *ctx)
{
	if (bpf_static_branch_unlikely(&key1))
		ret_user += 30;
	else
		ret_user += 40;

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_yet_another_prog(void *ctx)
{
	if (bpf_static_branch_unlikely(&key1))
		ret_user += 300;
	else
		ret_user += 400;

	return 0;
}

static __always_inline int big_chunk_of_code(volatile int *x)
{
	#pragma clang loop unroll_count(256)
	for (int i = 0; i < 256; i++)
		*x += 1;

	return *x;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_long_jump(void *ctx)
{
	int x;

	if (bpf_static_branch_likely(&key1)) {
		x = 1000;
		big_chunk_of_code(&x);
		ret_user = x;
	} else {
		x = 2000;
		big_chunk_of_code(&x);
		ret_user = x;
	}

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_multiple_keys_unlikely(void *ctx)
{
	ret_user = (bpf_static_branch_unlikely(&key1) << 0) |
		   (bpf_static_branch_unlikely(&key2) << 1) |
		   (bpf_static_branch_unlikely(&key3) << 2);

	return 0;
}

int __noinline patch(int x)
{
	if (bpf_static_branch_likely(&key1))
		x += 100;
	if (bpf_static_branch_unlikely(&key2))
		x += 1000;

	return x;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_bpf_to_bpf_call(void *ctx)
{
	__u64 j = bpf_jiffies64();

	bpf_printk("%lu\n", j);

	ret_user = 0;

	if (bpf_static_branch_likely(&key1))
		ret_user += 1;
	if (bpf_static_branch_unlikely(&key2))
		ret_user += 10;

	ret_user = patch(ret_user);

	return 0;
}

char _license[] SEC("license") = "GPL";
