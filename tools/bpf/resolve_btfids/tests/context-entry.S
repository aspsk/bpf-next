/* SPDX-License-Identifier: GPL-2.0-only */
.text
.globl native_untracked_caller
.type native_untracked_caller, %function
native_untracked_caller:
#if defined(__aarch64__)
	b global_unknown_caller
#elif defined(__x86_64__)
	jmp global_unknown_caller
#else
#error unsupported regression architecture
#endif
.size native_untracked_caller, .-native_untracked_caller

.data
.globl native_function_pointer
.type native_function_pointer, %object
native_function_pointer:
	.quad global_data_escape
.size native_function_pointer, .-native_function_pointer
.section .note.GNU-stack,"",%progbits
