/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_METADATA_H
#define FMODRET_METADATA_H

/* Fmod-ret descriptions shared by bpf_scan_ir and resolve_btfids.
 * Build-only, target-endian records in .BTF_fmodret_candidates.
 *
 * Function: u32 magic, version, size, flags; ptr function;
 *           u32 nr_calls, nr_params; followed by nr_params parameter records,
 *           then nr_calls call records.
 * Param:    u32 flags, reserved.
 * Call:     ptr callee; u32 flags, nr_cases, callee_param, nr_bindings;
 *           followed by nr_cases cases, then nr_bindings bindings.
 * Case:     s32 first_errno, last_errno; u32 kind; s32 replacement_errno.
 * Binding:  ptr function; u32 argument, source_param.
 *
 * All records use packed layout. Function records are pointer-aligned.
 * Cases partition [-4095, -1], including explicitly unknown intervals.
 * A null callee with callee_param != NO_PARAM calls a formal parameter;
 * otherwise it denotes an unresolved call or a compiler intrinsic. A binding
 * passes a function address (source_param == NO_PARAM) or forwards a formal
 * parameter (null function) into the specified zero-based argument position.
 * CLOSED parameters are only invoked, checked against null, or forwarded to
 * fixed arguments of direct calls. All their uses must be described.
 * Function RET64 distinguishes 64-bit integer results. Call result flags
 * distinguish 32-bit integers, 64-bit integers and pointers, for checking a
 * resolved callback's result representation before reusing its errno cases.
 * ADDRESS_TAKEN is diagnostic only. ESCAPED denotes an untracked use, not
 * merely taking an address or passing it through a described callback flow.
 *
 * CLEAN_SEED describes an existing side-effect-free errno path. CLEAN_PREFIX
 * covers entry through the instruction before the call. Error cases describe
 * all continuations after a failed call, irrespective of cleanup side effects.
 * UNKNOWN includes discarded results, unsupported expressions and loops.
 * Identity includes sign-preserving integer and ERR_PTR/PTR_ERR casts;
 * CONSTANT maps to an errno. NETLINK_ACK is a flag for paths ending at
 * netlink_ack() with a proven negative errno in its error argument. Any
 * remaining paths must satisfy the accompanying IDENTITY/CONSTANT mapping;
 * NETLINK_ACK alone means all paths report the error. Reported paths do not
 * contribute to clean-function derivation.
 * NETLINK_RCV is an endpoint flag for a callback returning an errno to
 * netlink_rcv_skb(). It describes framework handling, including the -EINTR
 * path without an ACK, rather than guaranteed error delivery to userspace.
 * Pointer results are propagation relays only.
 * These facts cover negative errno injection only, not arbitrary return values.
 */
#define FMODRET_META_MAGIC 0x46524d32U
#define FMODRET_META_VERSION 4U
#define FMODRET_META_ERRNOS 4095
#define FMODRET_META_HEADER_SIZE(ptr_size) (24 + (ptr_size))
#define FMODRET_META_PARAM_SIZE 8
#define FMODRET_META_CALL_SIZE(ptr_size) (16 + (ptr_size))
#define FMODRET_META_CASE_SIZE 16
#define FMODRET_META_BINDING_SIZE(ptr_size) (8 + (ptr_size))
#define FMODRET_NO_PARAM (~0U)

#define FMODRET_PARAM_CLOSED (1U << 0)

#define FMODRET_FN_DEFINED (1U << 0)
#define FMODRET_FN_LOCAL (1U << 1)
#define FMODRET_FN_CLEAN_SEED (1U << 2)
#define FMODRET_FN_ESCAPED (1U << 3)
#define FMODRET_FN_WEAK (1U << 4)
#define FMODRET_FN_INTEGER (1U << 5)
/* Error pointers can relay errno values without becoming injection candidates. */
#define FMODRET_FN_ERRPTR (1U << 6)
#define FMODRET_FN_RET64 (1U << 7)
#define FMODRET_FN_ADDRESS_TAKEN (1U << 8)
#define FMODRET_FN_FLAGS ((1U << 9) - 1)

#define FMODRET_CALL_CLEAN_PREFIX (1U << 0)
#define FMODRET_CALL_RESULT32 (1U << 1)
#define FMODRET_CALL_RESULT64 (1U << 2)
#define FMODRET_CALL_RESULT_PTR (1U << 3)
#define FMODRET_CALL_RESULT_MASK (FMODRET_CALL_RESULT32 | FMODRET_CALL_RESULT64 | \
				  FMODRET_CALL_RESULT_PTR)
#define FMODRET_CALL_FLAGS (FMODRET_CALL_CLEAN_PREFIX | FMODRET_CALL_RESULT_MASK)

#define FMODRET_ERROR_UNKNOWN 0
#define FMODRET_ERROR_IDENTITY 1
#define FMODRET_ERROR_CONSTANT 2
#define FMODRET_ERROR_RETURN_MASK 3
#define FMODRET_ERROR_NETLINK_ACK (1U << 2)
#define FMODRET_ERROR_NETLINK_RCV (1U << 3)
#define FMODRET_ERROR_ENDPOINTS (FMODRET_ERROR_NETLINK_ACK | FMODRET_ERROR_NETLINK_RCV)

#endif
