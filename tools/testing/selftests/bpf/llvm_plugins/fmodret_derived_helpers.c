// SPDX-License-Identifier: GPL-2.0-only
#include "fmodret_derived.h"

int derived_state;
int (*derived_saved_callback)(int);

DERIVED_HELPER int derived_seed(int value)
{
	return value ? -EINVAL : 0;
}

DERIVED_HELPER void *derived_pointer(int value)
{
	return value ? ERR_PTR(-EINVAL) : NULL;
}

DERIVED_HELPER int derived_relay(int value)
{
	return derived_seed(value);
}

DERIVED_HELPER int derived_dispatch(int (*callback)(int), int value)
{
	return callback(value);
}

DERIVED_HELPER int derived_forward(int (*callback)(int), int value)
{
	return derived_dispatch(callback, value);
}

DERIVED_HELPER int derived_escaping_dispatch(int (*callback)(int), int value)
{
	derived_saved_callback = callback;
	return callback(value);
}

DERIVED_HELPER int derived_ignoring_dispatch(int (*callback)(int), int value)
{
	callback(value);
	return 0;
}

DERIVED_HELPER int derived_cycle_a(int value)
{
	return value ? derived_cycle_b(value - 1) : 0;
}

DERIVED_HELPER int derived_cycle_b(int value)
{
	return value ? derived_cycle_a(value - 1) : 0;
}

static DERIVED_HELPER int swallow_entry(int value)
{
	fmodret_derived_unsafe_swallowed_by_caller(value);
	return 0;
}

/* Runtime pointer storage is deliberately outside the described call graph. */
void *derived_operations[] __used = {
	fmodret_derived_unsafe_escaped_address,
};

/*
 * Synthetic syscall boundaries; these objects are compiled and never loaded.
 * Syscall entries are not fmod_ret targets themselves, so each tested function
 * is reached through a wrapper entry which returns its result unchanged.
 */
#define DERIVED_TESTED(X)				\
	X(fmodret_derived_safe_direct)			\
	X(fmodret_derived_safe_translation)		\
	X(fmodret_derived_safe_pointer)			\
	X(fmodret_derived_safe_multihop)		\
	X(fmodret_derived_safe_allocation)		\
	X(fmodret_derived_safe_callback)		\
	X(fmodret_derived_safe_forwarded_callback)	\
	X(fmodret_derived_unsafe_dirty_prefix)		\
	X(fmodret_derived_unsafe_opaque_prefix)		\
	X(fmodret_derived_unsafe_swallowed_result)	\
	X(fmodret_derived_unsafe_nonerror_result)	\
	X(fmodret_derived_unsafe_atomic_prefix)		\
	X(fmodret_derived_unsafe_unknown_allocator)	\
	X(fmodret_derived_unsafe_dirty_allocation)	\
	X(fmodret_derived_unsafe_escaped_callback)	\
	X(fmodret_derived_unsafe_ignored_callback)	\
	X(fmodret_derived_unsafe_escaped_address)	\
	X(fmodret_derived_unsafe_unseeded_cycle)

#define DERIVED_ENTRY(fn)				\
	DERIVED_HELPER long derived_entry_##fn(int value)	\
	{						\
		return fn(value);			\
	}
DERIVED_TESTED(DERIVED_ENTRY)

#define DERIVED_TABLE_ENTRY(fn) derived_entry_##fn,
void *sys_call_table[] __used = {
	DERIVED_TESTED(DERIVED_TABLE_ENTRY)
	swallow_entry,
};
