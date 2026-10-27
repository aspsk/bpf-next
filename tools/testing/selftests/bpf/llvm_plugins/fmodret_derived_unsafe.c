// SPDX-License-Identifier: GPL-2.0-only
/* Observable effects or missing propagation proofs must prevent admission. */
#include "fmodret_derived.h"

FMODRET_TEST int fmodret_derived_unsafe_dirty_prefix(int value)
{
	derived_state = value;
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_unsafe_opaque_prefix(int value)
{
	derived_opaque_effect();
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_unsafe_swallowed_result(int value)
{
	derived_seed(value);
	return 0;
}

FMODRET_TEST int fmodret_derived_unsafe_nonerror_result(int value)
{
	derived_seed(value);
	return 1;
}

FMODRET_TEST int fmodret_derived_unsafe_atomic_prefix(int value)
{
	__atomic_fetch_add(&derived_state, 1, __ATOMIC_RELAXED);
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_unsafe_unknown_allocator(int value)
{
	void *ptr = derived_unknown_allocator((unsigned long)value, 0);

	return ptr ? 0 : -ENOMEM;
}

FMODRET_TEST int fmodret_derived_unsafe_dirty_allocation(int value)
{
	derived_state = value;
	return __kmalloc_large_noprof((unsigned long)value, 0) ? 0 : -ENOMEM;
}

FMODRET_TEST int fmodret_derived_unsafe_escaped_callback(int value)
{
	return derived_escaping_dispatch(derived_seed, value);
}

FMODRET_TEST int fmodret_derived_unsafe_ignored_callback(int value)
{
	return derived_ignoring_dispatch(derived_seed, value);
}

/* These bodies are derived clean, but their caller coverage fails. */
FMODRET_TEST int fmodret_derived_unsafe_swallowed_by_caller(int value)
{
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_unsafe_escaped_address(int value)
{
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_unsafe_unseeded_cycle(int value)
{
	return derived_cycle_a(value);
}
