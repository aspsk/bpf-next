/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_METADATA_H
#define FMODRET_METADATA_H

/* Fmod-ret descriptions shared by bpf_scan_ir and resolve_btfids.
 * Build-only, target-endian records in .BTF_fmodret_candidates.
 *
 * Function: u32 magic, version, size, flags; ptr function;
 *           u32 nr_calls, reserved; followed by nr_calls call records.
 * Call:     ptr callee; u32 flags, nr_cases; followed by nr_cases cases.
 * Case:     s32 first_errno, last_errno; u32 kind; s32 replacement_errno.
 *
 * All records use packed layout. Function records are pointer-aligned.
 * Cases partition [-4095, -1], including explicitly unknown intervals.
 * A null callee denotes an unresolved call or a compiler intrinsic.
 *
 * CLEAN_SEED describes an existing side-effect-free errno path. CLEAN_PREFIX
 * covers entry through the instruction before the call. Error cases describe
 * all continuations after a failed call, irrespective of cleanup side effects.
 * UNKNOWN includes discarded results, unsupported expressions and loops.
 * Identity includes sign-preserving integer and ERR_PTR/PTR_ERR casts;
 * CONSTANT maps to an errno. Pointer results are propagation relays only.
 * These facts cover negative errno injection only, not arbitrary return values.
 */
#define FMODRET_META_MAGIC 0x46524d32U
#define FMODRET_META_VERSION 1U
#define FMODRET_META_ERRNOS 4095
#define FMODRET_META_HEADER_SIZE(ptr_size) (24 + (ptr_size))
#define FMODRET_META_CALL_SIZE(ptr_size) (8 + (ptr_size))
#define FMODRET_META_CASE_SIZE 16

#define FMODRET_FN_DEFINED (1U << 0)
#define FMODRET_FN_LOCAL (1U << 1)
#define FMODRET_FN_CLEAN_SEED (1U << 2)
#define FMODRET_FN_ESCAPED (1U << 3)
#define FMODRET_FN_WEAK (1U << 4)
#define FMODRET_FN_INTEGER (1U << 5)
/* Error pointers can relay errno values without becoming injection candidates. */
#define FMODRET_FN_ERRPTR (1U << 6)
#define FMODRET_FN_FLAGS ((1U << 7) - 1)

#define FMODRET_CALL_CLEAN_PREFIX (1U << 0)

#define FMODRET_ERROR_UNKNOWN 0
#define FMODRET_ERROR_IDENTITY 1
#define FMODRET_ERROR_CONSTANT 2

#endif
