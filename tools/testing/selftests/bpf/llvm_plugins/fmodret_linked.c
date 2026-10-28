// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>

#if defined(TEST_X64_ENTRY)
#define LINKED_ENTRY __x64_sys_fmodret_linked
#elif defined(TEST_X64_COMPAT_ENTRY)
#define LINKED_ENTRY __x64_compat_sys_fmodret_linked
#elif defined(TEST_IA32_ENTRY)
#define LINKED_ENTRY __ia32_sys_fmodret_linked
#elif defined(TEST_IA32_COMPAT_ENTRY)
#define LINKED_ENTRY __ia32_compat_sys_fmodret_linked
#elif defined(TEST_FAKE_ENTRY)
#define LINKED_ENTRY __x64_syscall_fmodret_linked
#else
#define LINKED_ENTRY fmodret_linked_entry
#endif

__used noinline int fmodret_linked_leaf(int value)
{
	if (value)
		return -22;
#ifdef TEST_BUG
#ifdef __x86_64__
	asm volatile(".globl fmodret_linked_bug\nfmodret_linked_bug: ud2");
#elif defined(__aarch64__)
	asm volatile(".globl fmodret_linked_bug\nfmodret_linked_bug: brk #0x800");
#endif
#endif
	return 0;
}

#ifdef TEST_LOCAL_ENTRY
static
#endif
__used noinline long LINKED_ENTRY(int value)
{
#ifdef TEST_SWALLOW
	fmodret_linked_leaf(value);
	return 0;
#else
	return fmodret_linked_leaf(value);
#endif
}

#if defined(TEST_NO_BOUNDARY)
void *linked_operations[] __used = { LINKED_ENTRY };
#elif !defined(TEST_NO_TABLE)
void *sys_call_table[] __used = { LINKED_ENTRY };
#endif

#if defined(TEST_DISPATCHER) || defined(TEST_BAD_CALLER)
long linked_result;

__used noinline void fmodret_linked_dispatcher(int value)
{
#ifdef TEST_BAD_CALLER
	linked_result = fmodret_linked_leaf(value);
#else
	linked_result = LINKED_ENTRY(value);
#endif
}
#endif
