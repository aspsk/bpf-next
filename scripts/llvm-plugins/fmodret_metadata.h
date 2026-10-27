/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_METADATA_H
#define FMODRET_METADATA_H

/* Packed target-endian records, aligned to the target pointer size.
 * Function: u32 magic, version, size, flags; ptr function;
 *           u32 nr_calls, nr_params; Param params[]; Call calls[].
 * Call: ptr callee; u32 flags, nr_cases, callee_param, nr_bindings;
 *       Case cases[]; Binding bindings[].
 * Case: s32 first_errno, last_errno; u32 kind; s32 replacement_errno.
 * Param: u32 flags, reserved.
 * Binding: ptr function; u32 argument, source_param.
 * Cases partition [-4095, -1], including unknown outcomes.
 */
#define FMODRET_META_MAGIC 0x46524d32U
#define FMODRET_META_VERSION 3U
#define FMODRET_META_ERRNOS 4095
#define FMODRET_META_HEADER_SIZE(ptr_size) (24 + (ptr_size))
#define FMODRET_META_CALL_SIZE(ptr_size) (16 + (ptr_size))
#define FMODRET_META_CASE_SIZE 16
#define FMODRET_META_PARAM_SIZE 8
#define FMODRET_META_BINDING_SIZE(ptr_size) (8 + (ptr_size))
#define FMODRET_PARAM_CLOSED (1U << 0)
#define FMODRET_NO_PARAM (~0U)

#define FMODRET_FN_DEFINED (1U << 0)
#define FMODRET_FN_LOCAL (1U << 1)
#define FMODRET_FN_CLEAN_SEED (1U << 2)
#define FMODRET_FN_ESCAPED (1U << 3)
#define FMODRET_FN_WEAK (1U << 4)
#define FMODRET_FN_INTEGER (1U << 5)
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

#endif
