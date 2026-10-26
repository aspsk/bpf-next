// SPDX-License-Identifier: GPL-2.0-only
/* Regression inputs for positive ownership and real invalidation boundaries. */
#define NOINLINE __attribute__((noinline))
#define ACQUIRE(x) __attribute__((acquire_capability(x)))
#define RELEASE(x) __attribute__((release_capability(x)))

#ifdef TEST_SPIN_CONTEXT
#define test_lock spinlock
#define TEST_CAPABILITY "spinlock"
#else
#define TEST_CAPABILITY "mutex"
#endif

#ifdef TEST_REGISTER_NUMBER_ASM
asm(".irp num,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30\n"
    ".equ .L__gpr_num_x\\num, \\num\n"
    ".equ .L__gpr_num_w\\num, \\num\n"
    ".endr\n"
    ".equ .L__gpr_num_xzr, 31\n"
    ".equ .L__gpr_num_wzr, 31\n");
#endif
#ifdef TEST_UNKNOWN_REPEAT_ASM
asm(".irp num,0\n.equ .Lunknown_\\num, \\num\n.endr\n");
#endif

struct __attribute__((capability(TEST_CAPABILITY))) test_lock { int state; };
struct test_object {
	struct test_lock lock;
	volatile int counter;
	struct test_object *next;
};

void test_lock(struct test_lock *lock) ACQUIRE(lock);
void test_unlock(struct test_lock *lock) RELEASE(lock);
int test_trylock(struct test_lock *lock) __attribute__((try_acquire_capability(1, lock)));
void opaque(struct test_object *obj);

static NOINLINE int after_store(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_work(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_unlock(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_corruption(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_opaque(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_alias(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_loop(struct test_object *obj) { return obj->counter; }

static NOINLINE void update_counter(struct test_object *obj)
{
	obj->counter++;
}

int store_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	obj->counter++;
	ret = after_store(obj);
	test_unlock(&obj->lock);
	return ret;
}

int work_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	update_counter(obj);
	ret = after_work(obj);
	test_unlock(&obj->lock);
	return ret;
}

int unlock_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	test_unlock(&obj->lock);
	return after_unlock(obj);
}

int corruption_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	obj->lock.state = 0;
	return after_corruption(obj);
}

int opaque_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	opaque(obj);
	return after_opaque(obj);
}

int alias_case(struct test_object *obj, struct test_object *other)
{
	test_lock(&obj->lock);
	other->lock.state = 0;
	return after_alias(obj);
}

int loop_case(struct test_object *obj, int count)
{
	int ret;

	test_lock(&obj->lock);
	while (count-- > 0)
		obj->counter++;
	ret = after_loop(obj);
	test_unlock(&obj->lock);
	return ret;
}

struct test_holder { struct test_object *volatile current; };

static NOINLINE int after_capture(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_reload(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_replacement(struct test_object *obj) { return obj->counter; }

int capture_case(struct test_holder *holder)
{
	struct test_object *obj = holder->current;
	int ret;

	test_lock(&obj->lock);
	ret = after_capture(obj);
	test_unlock(&obj->lock);
	return ret;
}

int reload_case(struct test_holder *holder)
{
	struct test_object *obj = holder->current;
	int ret;

	test_lock(&obj->lock);
	ret = after_reload(holder->current);
	test_unlock(&obj->lock);
	return ret;
}

int replacement_case(struct test_holder *holder, struct test_object *other)
{
	struct test_object *obj = holder->current;
	int ret;

	test_lock(&obj->lock);
	holder->current = other;
	ret = after_replacement(holder->current);
	test_unlock(&obj->lock);
	return ret;
}

static NOINLINE int selected_a(struct test_object *obj) { return obj->counter; }
static NOINLINE int selected_b(struct test_object *obj) { return obj->counter; }
static NOINLINE int mixed_context(struct test_object *obj) { return obj->counter; }
static NOINLINE int escaped_callback(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_recursive(struct test_object *obj) { return obj->counter; }

void register_callback(int (*fn)(struct test_object *));

int selector_case(struct test_object *obj, int choose)
{
	int ret;
	int (*fn)(struct test_object *) = choose ? selected_a : selected_b;

	test_lock(&obj->lock);
	ret = fn(obj);
	test_unlock(&obj->lock);
	return ret;
}

int mixed_locked_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	ret = mixed_context(obj);
	test_unlock(&obj->lock);
	return ret;
}

int mixed_unlocked_case(struct test_object *obj)
{
	return mixed_context(obj);
}

int escaped_case(struct test_object *obj)
{
	int ret;

	register_callback(escaped_callback);
	test_lock(&obj->lock);
	ret = escaped_callback(obj);
	test_unlock(&obj->lock);
	return ret;
}

static NOINLINE void recursive_update(struct test_object *obj, int count)
{
	obj->counter++;
	if (count > 0)
		recursive_update(obj, count - 1);
}

int recursive_case(struct test_object *obj, int count)
{
	int ret;

	test_lock(&obj->lock);
	recursive_update(obj, count);
	ret = after_recursive(obj);
	test_unlock(&obj->lock);
	return ret;
}

struct test_object global_a, global_b;
extern struct test_object global_alias __attribute__((alias("global_a")));

static NOINLINE int after_global(void) { return global_a.counter; }
static NOINLINE int after_global_alias(void) { return global_a.counter; }

int global_case(void)
{
	int ret;

	test_lock(&global_a.lock);
	global_b.counter++;
	ret = after_global();
	test_unlock(&global_a.lock);
	return ret;
}

int global_alias_case(void)
{
	test_lock(&global_a.lock);
	global_alias.lock.state = 0;
	return after_global_alias();
}

static NOINLINE int after_pending(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_pending_corruption(struct test_object *obj) { return obj->counter; }

int pending_case(struct test_object *obj)
{
	int locked = test_trylock(&obj->lock);
	int ret = 0;

	update_counter(obj);
	if (locked) {
		ret = after_pending(obj);
		test_unlock(&obj->lock);
	}
	return ret;
}

int pending_corruption_case(struct test_object *obj)
{
	int locked = test_trylock(&obj->lock);

	obj->lock.state = 0;
	return locked ? after_pending_corruption(obj) : 0;
}

static NOINLINE int after_unknown_release(struct test_object *obj) { return obj->counter; }

int unknown_release_case(struct test_object *obj, struct test_object *other, int choose)
{
	test_lock(&obj->lock);
	test_unlock(choose ? &obj->lock : &other->lock);
	return after_unknown_release(obj);
}

struct __attribute__((capability("outer"))) nested_lock {
	int owner;
	struct test_lock inner;
	volatile int counter;
};

void take_outer(struct nested_lock *lock) ACQUIRE(lock);
void drop_outer(struct nested_lock *lock) RELEASE(lock);
static NOINLINE int after_inner_release(struct nested_lock *obj) { return obj->counter; }
static NOINLINE int after_inner_write(struct nested_lock *obj) { return obj->counter; }

int nested_case(struct nested_lock *obj)
{
	int ret;

	take_outer(obj);
	test_lock(&obj->inner);
	test_unlock(&obj->inner);
	ret = after_inner_release(obj);
	drop_outer(obj);
	return ret;
}

int nested_write_case(struct nested_lock *obj)
{
	take_outer(obj);
	obj->inner.state = 0;
	return after_inner_write(obj);
}

int try_outer(struct nested_lock *lock) __attribute__((try_acquire_capability(1, lock)));
static NOINLINE int after_pending_inner(struct nested_lock *obj) { return obj->counter; }

int pending_nested_case(struct nested_lock *obj)
{
	int locked = try_outer(obj);
	int ret = 0;

	test_lock(&obj->inner);
	test_unlock(&obj->inner);
	if (locked) {
		ret = after_pending_inner(obj);
		drop_outer(obj);
	}
	return ret;
}

struct __attribute__((capability("wrapper"))) wrapped_lock {
	struct test_lock inner;
	volatile int counter;
};

void take_wrapper(struct wrapped_lock *lock) ACQUIRE(lock);
static NOINLINE int after_alias_release(struct wrapped_lock *obj) { return obj->counter; }

int alias_release_case(struct wrapped_lock *obj)
{
	take_wrapper(obj);
	test_unlock(&obj->inner);
	return after_alias_release(obj);
}

static NOINLINE void acquire_from_holder(struct test_holder *holder)
{
	test_lock(&holder->current->lock);
}

static NOINLINE int after_foreign_snapshot(struct test_object *obj) { return obj->counter; }

int foreign_snapshot_case(struct test_holder *first, struct test_holder *second)
{
	struct test_object *obj = first->current;

	acquire_from_holder(second);
	return after_foreign_snapshot(obj);
}

static NOINLINE int after_stack_memory(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_memory_barrier(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_register_read(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_memory_corruption(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_unrecognized_asm(struct test_object *obj) { return obj->counter; }

static NOINLINE void stack_memory(void)
{
	char storage[64];

	__builtin_memset(storage, 0, sizeof(storage));
	asm volatile("" : : "r"(storage) : "memory");
}

int stack_memory_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	stack_memory();
	return after_stack_memory(obj);
}

int memory_barrier_case(struct test_object *obj)
{
	test_lock(&obj->lock);
#if defined(__aarch64__)
	asm volatile("dmb ishld" : : : "memory");
#elif defined(__x86_64__)
	asm volatile("lfence" : : : "memory");
#endif
	return after_memory_barrier(obj);
}

static NOINLINE unsigned long read_thread_register(void)
{
#if defined(__aarch64__)
	unsigned long value;

	asm volatile("mrs %0, sp_el0" : "=r"(value));
	return value;
#else
	return 0;
#endif
}

int register_read_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	obj->counter += read_thread_register();
	return after_register_read(obj);
}

int memory_corruption_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	__builtin_memset(&obj->lock, 0, sizeof(obj->lock));
	return after_memory_corruption(obj);
}

int unrecognized_asm_case(struct test_object *obj)
{
	test_lock(&obj->lock);
	asm volatile("nop" : : : "memory");
	return after_unrecognized_asm(obj);
}

NOINLINE int global_locked(struct test_object *obj) { return obj->counter; }
NOINLINE int global_mixed(struct test_object *obj) { return obj->counter; }
NOINLINE int global_unknown_caller(struct test_object *obj) { return obj->counter; }
NOINLINE int global_data_escape(struct test_object *obj) { return obj->counter; }

int global_locked_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	ret = global_locked(obj);
	test_unlock(&obj->lock);
	return ret;
}

int global_mixed_locked_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	ret = global_mixed(obj);
	test_unlock(&obj->lock);
	return ret;
}

int global_mixed_unlocked_case(struct test_object *obj)
{
	return global_mixed(obj);
}

int global_unknown_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	ret = global_unknown_caller(obj);
	test_unlock(&obj->lock);
	return ret;
}

int global_escape_case(struct test_object *obj)
{
	int ret;

	test_lock(&obj->lock);
	ret = global_data_escape(obj);
	test_unlock(&obj->lock);
	return ret;
}

/* A captured pointee is not the holder's by-value storage. */
struct separate_holder { struct test_object *object; volatile int state; };
struct embedded_holder { volatile int state; struct test_object *object; };
union overlay_holder { struct embedded_holder holder; struct test_lock lock; };
union overlay_holder overlay_instance;
static NOINLINE int after_holder_write(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_holder_call(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_union_write(struct test_object *obj) { return obj->counter; }
static NOINLINE int after_scalar_write(struct test_object *obj) { return obj->counter; }
static NOINLINE void holder_update(struct separate_holder *holder) { holder->state++; }
int holder_write_case(struct separate_holder *holder)
{
	struct test_object *obj = holder->object;
	test_lock(&obj->lock);
	holder->state++;
	return after_holder_write(obj);
}
int holder_call_case(struct separate_holder *holder)
{
	struct test_object *obj = holder->object;
	test_lock(&obj->lock);
	holder_update(holder);
	return after_holder_call(obj);
}
int union_write_case(struct embedded_holder *holder)
{
	struct test_object *obj = holder->object;
	test_lock(&obj->lock);
	holder->state++;
	return after_union_write(obj);
}
int scalar_write_case(struct separate_holder *holder, volatile int *alias)
{
	struct test_object *obj = holder->object;
	test_lock(&obj->lock);
	*alias = 0;
	return after_scalar_write(obj);
}
