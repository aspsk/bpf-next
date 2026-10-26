// SPDX-License-Identifier: GPL-2.0-only
#define NOINLINE __attribute__((noinline))
struct __attribute__((capability("spinlock"))) spinlock { int state; };
struct dispatch_object { struct spinlock lock; volatile int value; };
void lock_object(struct spinlock *lock) __attribute__((acquire_capability(lock)));
void unlock_object(struct spinlock *lock) __attribute__((release_capability(lock)));

NOINLINE int callback_entry(struct dispatch_object *obj) { return obj->value; }
struct static_call_key { int (*func)(struct dispatch_object *); };
struct static_call_key __SCK__lsm_static_call_example_0;
#ifdef TEST_DISPATCH_TRAMPOLINE
extern int __SCT__lsm_static_call_example_0(struct dispatch_object *);
static int jump_key;
#ifdef TEST_DISPATCH_OPAQUE_TRAMP
#define TRAMP_BODY "movl $0, (%rdi); ret; int3; nop; nop; nop\n"
#else
#define TRAMP_BODY "ret; int3; nop; nop; nop\n"
#endif
asm(".pushsection .static_call.text, \"ax\"\n"
    ".align 4\n.globl __SCT__lsm_static_call_example_0\n"
    "__SCT__lsm_static_call_example_0:\n"
    TRAMP_BODY ".byte 0x0f, 0xb9, 0xcc\n"
    ".type __SCT__lsm_static_call_example_0, @function\n"
    ".size __SCT__lsm_static_call_example_0, . - __SCT__lsm_static_call_example_0\n"
    ".popsection\n");
static void *used_key __attribute__((used, section(".discard.addressable"))) =
	&__SCK__lsm_static_call_example_0;
#define DISPATCH(obj) __SCT__lsm_static_call_example_0(obj)
#else
#define DISPATCH(obj) __SCK__lsm_static_call_example_0.func(obj)
#endif
struct lsm_static_call { struct static_call_key *key; void *trampoline; };
struct lsm_static_calls_table { struct lsm_static_call example[1]; };
struct lsm_static_calls_table static_calls_table = {
	.example = {{ .key = &__SCK__lsm_static_call_example_0,
#ifdef TEST_DISPATCH_TRAMPOLINE
		.trampoline = __SCT__lsm_static_call_example_0,
#endif
	}},
};
union callback_options { int (*example)(struct dispatch_object *); };
struct security_hook_list { struct lsm_static_call *scalls; union callback_options hook; };
struct security_hook_list callback_registration[] = {{
	.scalls = static_calls_table.example,
	.hook.example = callback_entry,
}};

int locked_dispatch(struct dispatch_object *obj)
{
	int ret;

	lock_object(&obj->lock);
#ifdef TEST_DISPATCH_TRAMPOLINE
	asm goto("1: jmp %l[done] # objtool NOPs this\n"
		 ".pushsection __jump_table, \"aw\"\n.balign 8\n"
		 ".long 1b - .\n.long %l[done] - .\n.quad %c0 + %c1 + 2 - .\n.popsection\n"
		 : : "i" (&jump_key), "i" (0) : : done);
#endif
	ret = DISPATCH(obj);
#ifdef TEST_DISPATCH_TRAMPOLINE
done:
#endif
	unlock_object(&obj->lock);
	return ret;
}

/* A modelled caller must not mask an unclosed registration or dispatcher. */
int locked_direct(struct dispatch_object *obj)
{
	int ret;

	lock_object(&obj->lock);
	ret = callback_entry(obj);
	unlock_object(&obj->lock);
	return ret;
}
#ifdef TEST_DISPATCH_MIXED
int unlocked_direct(struct dispatch_object *obj) { return callback_entry(obj); }
#endif
#ifdef TEST_DISPATCH_ESCAPED
int (*other_callback)(struct dispatch_object *) = callback_entry;
#endif
#ifdef TEST_DISPATCH_KEY_ESCAPE
void *unmodelled_key(void) { return &__SCK__lsm_static_call_example_0; }
#endif
#ifdef TEST_DISPATCH_SIGNATURE
int unmatched_dispatch(void)
{
	return ((int (*)(void))__SCK__lsm_static_call_example_0.func)();
}
#endif
