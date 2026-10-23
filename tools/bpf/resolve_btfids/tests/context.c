// SPDX-License-Identifier: GPL-2.0-only
/* Regression inputs for positive ownership and real invalidation boundaries. */
#define NOINLINE __attribute__((noinline))
#define ACQUIRE(x) __attribute__((acquire_capability(x)))
#define RELEASE(x) __attribute__((release_capability(x)))

struct __attribute__((capability("mutex"))) test_lock { int state; };
struct test_object {
	struct test_lock lock;
	volatile int counter;
	struct test_object *next;
};

void test_lock(struct test_lock *lock) ACQUIRE(lock);
void test_unlock(struct test_lock *lock) RELEASE(lock);
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
