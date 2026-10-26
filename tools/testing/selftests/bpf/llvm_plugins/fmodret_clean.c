// SPDX-License-Identifier: GPL-2.0-only
/* Supported atomic patterns: every function must receive CLEAN_SEED. */
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/types.h>

#define FMODRET_TEST __used noinline

/* Constant error returns and supported return widths. */
FMODRET_TEST int fmodret_clean_constant(void)
{
	return -EINVAL;
}

FMODRET_TEST s64 fmodret_clean_wide(void)
{
	return -EFAULT;
}

FMODRET_TEST int fmodret_clean_first_errno(void)
{
	return -1;
}

FMODRET_TEST int fmodret_clean_last_errno(void)
{
	return -MAX_ERRNO;
}

FMODRET_TEST static int fmodret_clean_local(void)
{
	return -ENOENT;
}

/* A clean error exit may coexist with reads or a dirty success path. */
FMODRET_TEST int fmodret_clean_select(bool reject)
{
	return reject ? -EINVAL : 0;
}

FMODRET_TEST int fmodret_clean_before_store(int *result, int value)
{
	if (value < 0)
		return -EINVAL;
	*result = value;
	return 0;
}

FMODRET_TEST int fmodret_clean_join(int *result, int value)
{
	int ret;

	if (value < 0)
		ret = -EINVAL;
	else if (value > 32)
		ret = -ERANGE;
	else {
		*result = value;
		ret = 0;
	}
	return ret;
}

FMODRET_TEST int fmodret_clean_plain_load(const int *state)
{
	return *state ? -EINVAL : -ENOENT;
}

/* Error pointers and errno-preserving casts. */
FMODRET_TEST void *fmodret_clean_error_pointer(void)
{
	return ERR_PTR(-ENOMEM);
}

FMODRET_TEST void *fmodret_clean_pointer_select(bool reject)
{
	return reject ? ERR_PTR(-EINVAL) : NULL;
}

FMODRET_TEST long fmodret_clean_ptr_err(void *ptr, int *state)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	*state = 1;
	return 0;
}

FMODRET_TEST long fmodret_clean_signed_extend(int value)
{
	return (long)(value ? -EINVAL : -ENOENT);
}

FMODRET_TEST int fmodret_clean_truncate(long value)
{
	return (int)(value ? (long)-EINVAL : (long)-ENOENT);
}

FMODRET_TEST void *fmodret_clean_dynamic_err_ptr(bool reject)
{
	long error = reject ? -EINVAL : -ENOMEM;

	return ERR_PTR(error);
}

/* Nonconstant results bounded inside the errno domain. */
FMODRET_TEST int fmodret_clean_masked_errno(unsigned int value)
{
	return -1 - (value & 31);
}

FMODRET_TEST s64 fmodret_clean_masked_wide_errno(u64 value)
{
	return -1 - (value & 31);
}

/* Supported boolean conditions and assumptions. */
FMODRET_TEST int fmodret_clean_nested_select(bool a, bool b)
{
	return a ? (b ? -EINVAL : -ENOENT) : 0;
}

FMODRET_TEST int fmodret_clean_boolean_and(bool a, bool b)
{
	return a && b ? -EINVAL : 0;
}

FMODRET_TEST int fmodret_clean_boolean_or(bool a, bool b)
{
	return a || b ? -EINVAL : 0;
}

FMODRET_TEST int fmodret_clean_boolean_xor(bool a, bool b)
{
	return a != b ? -EINVAL : 0;
}

FMODRET_TEST int fmodret_clean_assume(int value)
{
	__builtin_assume(value > 0);
	return -EINVAL;
}

/* Private stack writes are clean. optnone keeps them present in LLVM IR. */
FMODRET_TEST __attribute__((optnone)) int fmodret_clean_private_store(int value)
{
	int scratch[2];

	scratch[0] = value;
	scratch[1] = 0;
	return -EINVAL;
}

FMODRET_TEST __attribute__((optnone)) int fmodret_clean_private_memset(void)
{
	char scratch[32];

	__builtin_memset(scratch, 0, sizeof(scratch));
	return -EINVAL;
}

FMODRET_TEST __attribute__((optnone)) int fmodret_clean_private_memcpy(const void *source)
{
	char scratch[32];

	__builtin_memcpy(scratch, source, sizeof(scratch));
	return -EINVAL;
}

FMODRET_TEST __attribute__((optnone)) int fmodret_clean_private_memmove(const void *source)
{
	char scratch[32];

	__builtin_memmove(scratch, source, sizeof(scratch));
	return -EINVAL;
}
