// SPDX-License-Identifier: GPL-2.0-only
/* Direct ownership interfaces and a separately compiled implementation. */
#ifdef WARN_CONTEXT_ANALYSIS
#define CAPABILITY __attribute__((capability("spinlock")))
#define ACQUIRE(x) __attribute__((acquire_capability(x)))
#define RELEASE(x) __attribute__((release_capability(x)))
#else
#define CAPABILITY
#define ACQUIRE(x)
#define RELEASE(x)
#endif

struct CAPABILITY spinlock { int state; };
void take_spin(struct spinlock *lock) ACQUIRE(lock);
void drop_spin(struct spinlock *lock) RELEASE(lock);
#ifdef CONTEXT_PROVIDER_DISABLE
void legacy_update(void) __attribute__((no_thread_safety_analysis));
#else
void legacy_update(void);
#endif
void legacy_unlock(struct spinlock *lock) RELEASE(lock);
void unchecked_interface(void) __attribute__((no_thread_safety_analysis));
void unknown_external(void);

#ifdef CONTEXT_PROVIDER
volatile int legacy_counter;
void legacy_update(void) { legacy_counter++; }
void legacy_unlock(struct spinlock *lock) { lock->state = 0; }
void unchecked_interface(void) { legacy_counter++; }
#else
static __attribute__((noinline)) int after_legacy(struct spinlock *lock) { return lock->state; }
static __attribute__((noinline)) int after_legacy_unlock(struct spinlock *lock) { return lock->state; }
static __attribute__((noinline)) int after_unchecked(struct spinlock *lock) { return lock->state; }
static __attribute__((noinline)) int after_external(struct spinlock *lock) { return lock->state; }

int legacy_case(struct spinlock *lock)
{
	take_spin(lock);
	legacy_update();
	return after_legacy(lock);
}

int legacy_unlock_case(struct spinlock *lock)
{
	take_spin(lock);
	legacy_unlock(lock);
	return after_legacy_unlock(lock);
}

int unchecked_case(struct spinlock *lock)
{
	take_spin(lock);
	unchecked_interface();
	return after_unchecked(lock);
}

int external_case(struct spinlock *lock)
{
	take_spin(lock);
	unknown_external();
	return after_external(lock);
}
#endif
