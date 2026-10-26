/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_CONTEXT_H
#define _LINUX_BPF_CONTEXT_H

#include <linux/types.h>

struct bpf_verifier_env;
struct bpf_reg_state;
struct bpf_insn;
struct btf;
struct bpf_context_state;

int bpf_context_init(struct bpf_verifier_env *env);
void bpf_context_free(struct bpf_verifier_env *env);
u32 bpf_context_argument(struct bpf_verifier_env *env, u32 arg);
u32 bpf_context_load(struct bpf_verifier_env *env, u32 source, s64 offset, bool pointer);
void bpf_context_alu(struct bpf_verifier_env *env, const struct bpf_insn *insn,
		     u32 dst_id, u32 src_id);
int bpf_context_check_kfunc(struct bpf_verifier_env *env, struct btf *btf,
			    u32 func_id, const char *name);

#endif
