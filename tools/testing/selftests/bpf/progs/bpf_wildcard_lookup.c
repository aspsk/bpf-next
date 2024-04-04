// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

/*
 * This is only one test in which we want to compare cilium firewall
 * (6 hash lookups) vs. wildcard map lookup.
 *
 * TBD: later we can add another test to compare LPM vs wildcard map.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define MAX_ENTRIES 1024 /* XXX */

#if 0
BPF_WILDCARD_DESC_4(
        fw,
        BPF_WILDCARD_RULE_WILDCARD_MATCH, __u32, sec_identity,
        BPF_WILDCARD_RULE_WILDCARD_MATCH, __u16, dport,
        BPF_WILDCARD_RULE_WILDCARD_MATCH, __u8, protocol,
        BPF_WILDCARD_RULE_MATCH, __u8, egress,
);

struct {
        __uint(type, BPF_MAP_TYPE_WILDCARD);
        __type(key, struct fw_key);
        __type(value, __u64);
        __uint(max_entries, MAX_ENTRIES);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} fw __section(".maps");
#endif

struct fw_hash_key {
        __u32 sec_identity;
        __u16 dport;
        __u8 protocol;
        __u8 egress;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct fw_hash_key);
        __type(value, __u64);
        __uint(max_entries, MAX_ENTRIES);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} fw_hash SEC(".maps");

/* The number of slots to store times */
#define NR_SLOTS 32
#define NR_CPUS 256
#define CPU_MASK (NR_CPUS-1)

/* Configured by userspace */
u64 nr_entries;
u64 nr_loops;
u32 __attribute__((__aligned__(8))) key[NR_CPUS];

/* Filled by us */
u64 __attribute__((__aligned__(256))) percpu_times_index[NR_CPUS];
u64 __attribute__((__aligned__(256))) percpu_times[NR_CPUS][NR_SLOTS];

#if 0
static inline void patch_key(u32 i)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	key[0] = i + 1;
#else
	key[0] = __builtin_bswap32(i + 1);
#endif
	/* the rest of key is random and is configured by userspace */
}
#endif

#if 0
static int lookup_callback(__u32 index, u32 *unused)
{
	//patch_key(index);
	//return bpf_map_lookup_elem(&fw_hash, key) ? 0 : 1;
	return 0;
}

static int loop_lookup_callback(__u32 index, u32 *unused)
{
	return bpf_loop(nr_entries, lookup_callback, NULL, 0) ? 0 : 1;
}
#endif

__attribute__((noinline)) int __wurk(__u32 index)
{
	if (index > 0xffffff00)
		return 1;
	return 0;
}

static int noinline_callback(__u32 index, u32 *unused)
{
	return 0;//!!__wurk(index);
}

static int loop_noinline_callback(__u32 index, u32 *unused)
{
	return bpf_loop(nr_entries, noinline_callback, NULL, 0) ? 0 : 1;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int benchmark(void *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 times_index;
	u64 start_time;

	//bpf_loop(nr_loops, loop_lookup_callback, NULL, 0);

	times_index = percpu_times_index[cpu & CPU_MASK] % NR_SLOTS;
	start_time = bpf_ktime_get_ns();
	bpf_loop(nr_loops, loop_noinline_callback, NULL, 0);
	percpu_times[cpu & CPU_MASK][times_index] = bpf_ktime_get_ns() - start_time;
	percpu_times_index[cpu & CPU_MASK] += 1;
	return 0;
}
