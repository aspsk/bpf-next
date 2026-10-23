/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_CONTEXT_METADATA_H
#define BPF_CONTEXT_METADATA_H

/* Build-only, NUL-delimited JSON documents; never a runtime ABI. */
#define BPF_CONTEXT_SECTION ".bpf_context"
#define BPF_CONTEXT_FORMAT "bpf_context"
#define BPF_CONTEXT_VERSION 3
#define BPF_CONTEXT_IR_METADATA "bpf.context.source"

/* Runtime facts use ordinary BTF declaration tags on native FUNC/STRUCT types. */
#define BPF_CONTEXT_TAG_PREFIX "bpf_context:v1:"

#endif
