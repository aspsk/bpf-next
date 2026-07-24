// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "lsm_iter.h"

SEC("iter/bpf_lsm")
int iter(struct bpf_iter__bpf_lsm *ctx)
{
	struct bpf_lsm_info *info = ctx->lsm_info;
	struct lsm_iter_entry entry;

	if (!info)
		return 0;

	entry.btf_id = info->btf_id;
	entry.flags = info->flags;

	bpf_seq_write(ctx->meta->seq, &entry, sizeof(entry));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
