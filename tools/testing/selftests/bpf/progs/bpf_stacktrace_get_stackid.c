// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1000);
	__type(key, __u32);
	__type(value, __u64[120]);
} stack_trace_map_bench SEC(".maps");

/* The number of slots to store times */
#define NR_SLOTS 128

/* Filled by us */
u64 __attribute__((__aligned__(256))) percpu_times_index[NR_SLOTS];
u64 __attribute__((__aligned__(256))) percpu_times[256][NR_SLOTS];

/* Configured by userspace */
u64 nr_loops;

static int loop_lookup_callback(__u32 index, void *ctx_ptr)
{
	int ret;

	ret = bpf_get_stackid(* (void **)ctx_ptr, &stack_trace_map_bench, 0);

	return 0;
}

char __attribute__((__aligned__(256))) buf[256][512];

static inline int strcmp(char *s1, char *s2)
{
	int i;

	for (i = 0; i < 32 && s1[i] && s2[i] && s1[i] == s2[i]; i++) {
	}
	return s1[i] - s2[i];
}

#if 0
SEC("fentry/deep_stack_foo")
int BPF_PROG(benchmark, struct net *net, struct sock *sk, struct sk_buff *skb)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 times_index;
	u64 start_time;
	void *x = ctx;
	long ret;
	int i;

#if 0
	ret = bpf_d_path(&file->f_path, buf[cpu % 256], 512);
	if (!ret || __builtin_strcmp(buf[cpu % 256], "/dev/null"))
		return 0;
#endif

	times_index = percpu_times_index[cpu & 255] % NR_SLOTS;
	start_time = bpf_ktime_get_ns();
	bpf_loop(nr_loops, loop_lookup_callback, &x, 0);

	//for (i = 0; i < 100000; i++)
		//bpf_get_stackid(ctx, &stack_trace_map_bench, 0);

	percpu_times[cpu & 255][times_index] = bpf_ktime_get_ns() - start_time;
	percpu_times_index[cpu & 255] += 1;
	return 0;
}
#endif

SEC("kprobe/deep_stack_foo_08")
int BPF_PROG(benchmark, int i)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 times_index;
	u64 start_time;
	void *x = ctx;

	times_index = percpu_times_index[cpu & 255] % NR_SLOTS;
	start_time = bpf_ktime_get_ns();
	bpf_loop(nr_loops, loop_lookup_callback, &x, 0);
	percpu_times[cpu & 255][times_index] = bpf_ktime_get_ns() - start_time;
	percpu_times_index[cpu & 255] += 1;
	return 0;
}
