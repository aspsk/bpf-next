/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_SCAN_AST_METADATA_H
#define BPF_SCAN_AST_METADATA_H

/*
 * One NUL-terminated UTF-8 JSON document per translation unit, carried in a
 * used constant char array. No target pointers or relocations are embedded.
 * The linker concatenates documents in a non-allocating INFO section.
 * See bpf_scan_ast.rst for the versioned schema and its interpretation.
 */
#define BPF_SCAN_LOCK_SECTION ".bpf_scan.lock"
#define BPF_SCAN_LOCK_FORMAT "bpf_scan.lock"
#define BPF_SCAN_LOCK_VERSION 2

#endif
