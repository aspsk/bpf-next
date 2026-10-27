// SPDX-License-Identifier: GPL-2.0-only
/* Derived clean functions without a proved syscall propagation boundary. */
#include "fmodret_derived.h"

FMODRET_TEST int fmodret_derived_clean_direct(int value)
{
	return derived_seed(value);
}

FMODRET_TEST int fmodret_derived_clean_translation(int value)
{
	return derived_seed(value) ? -EIO : 0;
}

FMODRET_TEST int fmodret_derived_clean_pointer(int value)
{
	return PTR_ERR(derived_pointer(value));
}

FMODRET_TEST int fmodret_derived_clean_multihop(int value)
{
	return derived_relay(value);
}

FMODRET_TEST int fmodret_derived_clean_allocation(int value)
{
	void *ptr = __kmalloc_large_noprof((unsigned long)value, 0);

	return ptr ? 0 : -ENOMEM;
}
