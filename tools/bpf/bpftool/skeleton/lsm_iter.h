/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#ifndef __LSM_ITER_H
#define __LSM_ITER_H

enum lsm_iter_flags {
	LSM_ITER_F_DISABLED  = 1U << 0,
	LSM_ITER_F_BPF_ONLY  = 1U << 1,
	LSM_ITER_F_SLEEPABLE = 1U << 2,
};

struct lsm_iter_entry {
	__u32 btf_id;
	__u32 flags;
};

#endif /* __LSM_ITER_H */
