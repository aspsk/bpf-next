// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

int target_tgid;

/*
 * The same recursive-lock deadlock is known for security_task_setrlimit().
 * Its caller locks task->group_leader->alloc_lock. The analysis cannot yet
 * carry that captured owner into the hook and prove its identity with task,
 * so that case is not covered here yet.
 *
 * These are load-only tests: never attach a program that could deadlock.
 */
SEC("lsm/ptrace_access_check")
__failure
__msg("kfunc bpf_get_task_exe_file may deadlock: proven acquisition overlaps an entry-held lock")
int BPF_PROG(deadlock_ptrace, struct task_struct *child, unsigned int mode)
{
	struct file *f;

	if (!target_tgid || child->tgid != target_tgid)
		return 0;

	f = bpf_get_task_exe_file(child);
	if (f)
		bpf_put_file(f);
	return 0;
}

static __noinline int get_exe_file_static(struct task_struct *task)
{
	struct file *f = bpf_get_task_exe_file(task);

	if (f)
		bpf_put_file(f);
	return 0;
}

__noinline int get_exe_file_global(struct task_struct *task)
{
	return get_exe_file_static(task);
}

SEC("lsm/ptrace_access_check")
__failure
__msg("kfunc bpf_get_task_exe_file may deadlock: proven acquisition overlaps an entry-held lock")
int BPF_PROG(deadlock_ptrace_static, struct task_struct *child, unsigned int mode)
{
	return get_exe_file_static(child);
}

SEC("lsm/ptrace_access_check")
__failure
__msg("kfunc bpf_get_task_exe_file may deadlock: proven acquisition overlaps an entry-held lock")
int BPF_PROG(deadlock_ptrace_global, struct task_struct *child, unsigned int mode)
{
	return get_exe_file_global(child);
}

SEC("lsm/ptrace_access_check")
__failure
__msg("kfunc bpf_get_task_exe_file may deadlock: proven acquisition overlaps an entry-held lock")
int BPF_PROG(deadlock_ptrace_spilled, struct task_struct *child, unsigned int mode)
{
	struct task_struct * volatile saved = child;

	return get_exe_file_static(saved);
}

/* PF_KTHREAD, from include/linux/sched.h: the kfunc returns before locking. */
#define PF_KTHREAD 0x00200000

SEC("lsm/ptrace_access_check")
__success
int BPF_PROG(ptrace_kernel_thread, struct task_struct *child, unsigned int mode)
{
	struct file *f;

	if (!(child->flags & PF_KTHREAD))
		return 0;

	f = bpf_get_task_exe_file(child);
	if (f)
		bpf_put_file(f);
	return 0;
}

char _license[] SEC("license") = "GPL";
