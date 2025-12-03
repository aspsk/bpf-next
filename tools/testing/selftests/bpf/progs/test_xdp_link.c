// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
/* Copyright (c) 2025 Isovalent */
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

bool seen_xdp_ingress1;
bool seen_xdp_ingress2;

SEC("xdp")
int xdp_handler(struct xdp_md *xdp)
{
	return 0;
}

SEC("xdp/ingress")
int xdp_ingress1(struct xdp_md *xdp)
{
	seen_xdp_ingress1 = true;
	return XDP_NEXT;
}

SEC("xdp/ingress")
int xdp_ingress2(struct xdp_md *xdp)
{
	seen_xdp_ingress2 = true;
	return XDP_NEXT;
}

SEC("tc")
int tc_handler(struct __sk_buff *skb)
{
	volatile __u64  t = skb->tstamp;

	if (t % 2)
		return 0;
	if (t % 3)
		return 1;
	return 7;
}
