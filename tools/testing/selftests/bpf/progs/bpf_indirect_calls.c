// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__u64 ret_user;

static __u64 __noinline foo_1(__u64 x)
{
	return x * 17;
}

static __u64 __noinline foo_2(__u64 x)
{
	return x * 113;
}

struct simple_ctx {
	__u64 x;
};

SEC("syscall") int simple_test(struct simple_ctx *ctx)
{
	__u64 (*foo)(__u64);

	if (ctx->x % 2)
		foo = &foo_1;
	else
		foo = &foo_2;

	ret_user = foo(ctx->x);

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} calculon_input SEC(".maps");

struct calculon_ctx {
	__u64 n;
};

#define STACK_SIZE 9

struct calculon_stack {
	__u64 data[STACK_SIZE];
	int top;
};

static __noinline int push(struct calculon_stack *stack, __u64 value)
{
	if (stack->top < -1 || stack->top >= STACK_SIZE)
		return -22;

	stack->data[++stack->top] = value;
	return 0;
}

static __noinline int pop(struct calculon_stack *stack, __u64 *value)
{
	if (stack->top < 0 || stack->top > STACK_SIZE)
		return -22;

        *value = stack->data[stack->top--];
	return 0;
}

static __noinline int calculon_mul(struct calculon_stack *stack)
{
	__u64 x1, x2;

	if (pop(stack, &x1))
		return -1;
	if (pop(stack, &x2))
		return -1;

	return push(stack, x1 * x2);
}

static __noinline int calculon_add(struct calculon_stack *stack)
{
	__u64 x1, x2;

	if (pop(stack, &x1))
		return -1;
	if (pop(stack, &x2))
		return -1;

	return push(stack, x1 + x2);
}

static __noinline int calculon_sub(struct calculon_stack *stack)
{
	__u64 x1, x2;

	if (pop(stack, &x1))
		return -1;
	if (pop(stack, &x2))
		return -1;

	return push(stack, x1 - x2);
}

static inline bool isdigit(__u8 x)
{
	return x >= '0' && x <= '9';
}

SEC("syscall") int calculon(struct calculon_ctx *ctx)
{
	__u8 *x;
	int i, key;
	struct calculon_stack stack = {
		.top = -1,
	};
	int (*op)(struct calculon_stack *);

	for (i = 0; i < 1024 && i < ctx->n; i++) {
		key = i;

		x = bpf_map_lookup_elem(&calculon_input, &key);
		if (!x)
			break;

		if (isdigit(*x)) {
			if (push(&stack, *x - '0'))
				return -1;
			continue;
		} else if (*x == '*') {
			op = calculon_mul;
		} else if (*x == '+') {
			op = calculon_add;
		} else if (*x == '-') {
			op = calculon_sub;
		} else {
			return -1;
		}

		if (op(&stack))
			return -1;
	}

	return pop(&stack, &ret_user);
}

char _license[] SEC("license") = "GPL";
