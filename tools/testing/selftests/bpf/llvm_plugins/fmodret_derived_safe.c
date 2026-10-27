// SPDX-License-Identifier: GPL-2.0-only
/* Derived clean functions whose negative returns reach a syscall terminator. */
#include "fmodret_derived.h"

FMODRET_TEST int fmodret_derived_safe_direct(int value)
{
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_safe_translation(int value)
{
	return derived_seed(value) ? -EIO : 0;
}

FMODRET_TEST int fmodret_derived_safe_pointer(int value)
{
	return PTR_ERR(derived_pointer(value));
}

FMODRET_TEST int fmodret_derived_safe_multihop(int value)
{
	return derived_relay(value);
}

FMODRET_TEST int fmodret_derived_safe_allocation(int value)
{
	void *ptr = __kmalloc_large_noprof((unsigned long)value, 0);

	return ptr ? 0 : -ENOMEM;
}

FMODRET_TEST int fmodret_derived_safe_callback(int value)
{
	return derived_dispatch(derived_seed, value);
}

FMODRET_TEST int fmodret_derived_safe_forwarded_callback(int value)
{
	return derived_forward(derived_seed, value);
}
