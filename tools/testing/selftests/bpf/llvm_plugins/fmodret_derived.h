/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FMODRET_DERIVED_H
#define FMODRET_DERIVED_H

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/types.h>

#define FMODRET_TEST __used noinline
#define DERIVED_HELPER __used noinline

extern int derived_state;
extern void derived_opaque_effect(void);
extern void *__kmalloc_large_noprof(unsigned long size, unsigned int flags);
extern void *derived_unknown_allocator(unsigned long size, unsigned int flags);
int derived_seed(int value);
void *derived_pointer(int value);
int derived_relay(int value);
int derived_dispatch(int (*callback)(int), int value);
int derived_forward(int (*callback)(int), int value);
int derived_escaping_dispatch(int (*callback)(int), int value);
int derived_ignoring_dispatch(int (*callback)(int), int value);
int derived_cycle_a(int value);
int derived_cycle_b(int value);

int fmodret_derived_clean_direct(int value);
int fmodret_derived_clean_translation(int value);
int fmodret_derived_clean_pointer(int value);
int fmodret_derived_clean_multihop(int value);
int fmodret_derived_clean_allocation(int value);

int fmodret_derived_safe_direct(int value);
int fmodret_derived_safe_translation(int value);
int fmodret_derived_safe_pointer(int value);
int fmodret_derived_safe_multihop(int value);
int fmodret_derived_safe_allocation(int value);
int fmodret_derived_safe_callback(int value);
int fmodret_derived_safe_forwarded_callback(int value);
int fmodret_derived_safe_exported(int value);

int fmodret_derived_unsafe_dirty_prefix(int value);
int fmodret_derived_unsafe_opaque_prefix(int value);
int fmodret_derived_unsafe_swallowed_result(int value);
int fmodret_derived_unsafe_nonerror_result(int value);
int fmodret_derived_unsafe_atomic_prefix(int value);
int fmodret_derived_unsafe_unknown_allocator(int value);
int fmodret_derived_unsafe_dirty_allocation(int value);
int fmodret_derived_unsafe_escaped_callback(int value);
int fmodret_derived_unsafe_ignored_callback(int value);
int fmodret_derived_unsafe_swallowed_by_caller(int value);
int fmodret_derived_unsafe_escaped_address(int value);
int fmodret_derived_unsafe_unseeded_cycle(int value);

#endif
