// SPDX-License-Identifier: GPL-2.0-only
/* Atomic rejection cases and known recognition gaps; no propagation tests.
 * fmodret_unsafe_* functions have an observable effect on every error path.
 * The clean patterns not yet supported are grouped at the end of this file.
 */
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#define FMODRET_TEST __used noinline

int fmodret_observable_state;
extern void fmodret_opaque_effect(void);

/* Observable stores and volatile accesses. */
FMODRET_TEST int fmodret_unsafe_argument_store(int *state)
{
	*state = 1;
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_global_store(void)
{
	fmodret_observable_state = 1;
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_volatile_store(int *state)
{
	WRITE_ONCE(*state, 1);
	return -EINVAL;
}

/* A volatile read can itself have device side effects. */
FMODRET_TEST int fmodret_unsafe_volatile_read(int *state)
{
	return READ_ONCE(*state) ? -EINVAL : -ERANGE;
}

/* Atomic operations. */
FMODRET_TEST int fmodret_unsafe_atomic(atomic_t *state)
{
	atomic_inc(state);
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_exchange(int *state)
{
	xchg(state, 1);
	return -EINVAL;
}

/* Opaque calls and assembly. */
FMODRET_TEST int fmodret_unsafe_opaque_call(void)
{
	fmodret_opaque_effect();
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_assembly(void)
{
	barrier();
	return -EINVAL;
}

/* Every feasible error exit is dirty. A clean success does not count. */
FMODRET_TEST int fmodret_unsafe_both_branches(int *state, bool choose)
{
	if (choose)
		*state = 1;
	else
		*state = 2;
	return -EINVAL;
}

/* A clean success path is not a clean errno path. */
FMODRET_TEST int fmodret_unsafe_only_error_is_dirty(int *state, bool reject)
{
	if (reject) {
		*state = 1;
		return -EINVAL;
	}
	return 0;
}

/* Lock ownership is not restored before the error return. */
FMODRET_TEST int fmodret_unsafe_lock_held(spinlock_t *lock)
{
	spin_lock(lock);
	return -EINVAL;
}

/* Error-pointer exits must be clean too. */
FMODRET_TEST void *fmodret_unsafe_error_pointer(int *state)
{
	*state = 1;
	return ERR_PTR(-ENOMEM);
}

/* Atomic recognition must not find an errno in an infeasible branch. */
/* An infeasible error branch cannot establish cleanliness. */
FMODRET_TEST int fmodret_unsafe_contradictory_select(int *state, int value)
{
	int ret = value > 0 && value < 0 ? -EINVAL : 0;

	if (!ret)
		*state = 1;
	return ret;
}

FMODRET_TEST int fmodret_unsafe_boolean_contradiction(int *state, bool value)
{
	if (value && !value)
		return -EINVAL;
	*state = 1;
	return 0;
}

/* Escaped locals and writes to caller-owned memory. */
FMODRET_TEST int fmodret_unsafe_stack_escape(void)
{
	int scratch;

	extern void fmodret_capture(int *ptr);
	fmodret_capture(&scratch);
	scratch = 1;
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_external_memcpy(void *dest, const void *source)
{
	__builtin_memcpy(dest, source, 32);
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_external_memmove(void *dest, const void *source)
{
	__builtin_memmove(dest, source, 32);
	return -EINVAL;
}

FMODRET_TEST int fmodret_unsafe_external_memset(void *dest)
{
	__builtin_memset(dest, 0, 32);
	return -EINVAL;
}

/*
 * TODO: Support the following clean patterns in future.
 * They must not receive CLEAN_SEED yet. Once recognized, move them to
 * fmodret_clean.c and rename them fmodret_clean_*.
 */
FMODRET_TEST int fmodret_todo_balanced_spinlock(spinlock_t *lock)
{
	spin_lock(lock);
	spin_unlock(lock);
	return -EINVAL;
}

FMODRET_TEST int fmodret_todo_balanced_mutex(struct mutex *lock)
{
	mutex_lock(lock);
	mutex_unlock(lock);
	return -EINVAL;
}

FMODRET_TEST int fmodret_todo_balanced_rcu(void)
{
	rcu_read_lock();
	rcu_read_unlock();
	return -EINVAL;
}

/* A bounded input errno has no side effects, but is not recognized yet. */
FMODRET_TEST int fmodret_todo_input_errno_range(int error)
{
	if (error >= -MAX_ERRNO && error < 0)
		return error;
	return 0;
}

/* Returning a guarded input pointer through a merged exit is not recognized. */
FMODRET_TEST void *fmodret_todo_is_err_join(void *ptr, int *state)
{
	if (IS_ERR(ptr))
		return ptr;
	*state = 1;
	return NULL;
}
