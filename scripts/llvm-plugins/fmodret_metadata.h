/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_METADATA_H
#define FMODRET_METADATA_H

/* Packed target-endian function records, aligned to the target pointer size:
 * u32 magic, version, size, flags; ptr function; u32 nr_calls, nr_params.
 * Local discovery emits zero calls and parameters.
 */
#define FMODRET_META_MAGIC 0x46524d32U
#define FMODRET_META_VERSION 1U
#define FMODRET_META_ERRNOS 4095
#define FMODRET_META_HEADER_SIZE(ptr_size) (24 + (ptr_size))

#define FMODRET_FN_DEFINED (1U << 0)
#define FMODRET_FN_LOCAL (1U << 1)
#define FMODRET_FN_CLEAN_SEED (1U << 2)
#define FMODRET_FN_WEAK (1U << 4)
#define FMODRET_FN_INTEGER (1U << 5)
#define FMODRET_FN_ERRPTR (1U << 6)
#define FMODRET_FN_RET64 (1U << 7)

#endif
