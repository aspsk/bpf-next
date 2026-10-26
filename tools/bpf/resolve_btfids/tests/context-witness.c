// SPDX-License-Identifier: GPL-2.0-only
#define NOINLINE __attribute__((noinline))
#define MASK 0x200000U
struct __attribute__((capability("spinlock"))) witness_lock { unsigned int state; };
struct witness_task { unsigned int flags; struct witness_lock lock; };
void witness_lock(struct witness_lock *lock) __attribute__((acquire_capability(lock)));
void witness_unlock(struct witness_lock *lock) __attribute__((release_capability(lock)));
void opaque_prefix(void);

NOINLINE void guarded(struct witness_task *task)
{
	if (task->flags & MASK)
		return;
	witness_lock(&task->lock);
	witness_unlock(&task->lock);
}
void wrapper(struct witness_task *task) { guarded(task); }
void wrong_instance(struct witness_task *task, struct witness_task *other) { guarded(other); }
void contradictory(struct witness_task *task)
{
	if (task->flags & MASK)
		guarded(task);
}
void opaque_first(struct witness_task *task) { opaque_prefix(); guarded(task); }
void unknown_guard(struct witness_task *task, int allow)
{
	if (allow)
		guarded(task);
}
void write_first(struct witness_task *task)
{
	*(volatile unsigned int *)&task->flags = 0;
	guarded(task);
}
void assumed(struct witness_task *task)
{
	__builtin_assume(task->flags & MASK);
	guarded(task);
}
void unreadable_prefix(struct witness_task *task, volatile unsigned int *unknown)
{
	(void)*unknown;
	guarded(task);
}
void unsupported_mask(struct witness_task *task)
{
	if ((task->flags & 3) != 0)
		guarded(task);
}
void extension_guard(struct witness_task *task, signed char *value)
{
	if (((int)*value & 0x100) == 0) {
		witness_lock(&task->lock);
		witness_unlock(&task->lock);
	}
}

void set_guard(struct witness_task *task)
{
	if (task->flags & MASK) {
		witness_lock(&task->lock);
		witness_unlock(&task->lock);
	}
}
