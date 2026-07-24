/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_LSM_ITER_H
#define __BPF_LSM_ITER_H

enum bpf_lsm_iter_flags {
	BPF_LSM_ITER_F_DISABLED		= 1U << 0,
	BPF_LSM_ITER_F_BPF_ONLY		= 1U << 1,
	BPF_LSM_ITER_F_SLEEPABLE	= 1U << 2,
};

struct bpf_lsm_iter_entry {
	__u32 btf_id;
	__u32 flags;
};

#endif /* __BPF_LSM_ITER_H */
