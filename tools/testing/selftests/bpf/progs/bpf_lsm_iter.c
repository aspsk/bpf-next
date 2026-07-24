// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_lsm_iter.h"

__u32 num_entries;
__u32 num_terminal;

SEC("iter/bpf_lsm")
int dump_bpf_lsm(struct bpf_iter__bpf_lsm *ctx)
{
	struct bpf_lsm_info *info = ctx->lsm_info;
	struct bpf_lsm_iter_entry entry;

	if (!info) {
		num_terminal++;
		return 0;
	}

	entry.btf_id = info->btf_id;
	entry.flags = info->flags;
	num_entries++;

	bpf_seq_write(ctx->meta->seq, &entry, sizeof(entry));
	return 0;
}

char _license[] SEC("license") = "GPL";
