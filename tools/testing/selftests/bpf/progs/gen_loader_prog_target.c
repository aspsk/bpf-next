// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* The targets are in test_pkt_access.c */

SEC("freplace/get_constant")
int gen_loader_freplace(long val)
{
	return 0;
}

SEC("fentry/test_pkt_access")
int gen_loader_fentry(void *ctx)
{
	return 0;
}

SEC("fexit/test_pkt_access")
int gen_loader_fexit(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
