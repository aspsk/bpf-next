// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>

struct obj_get_args {
	char path[PATH_MAX];
	__u32 file_flags;
	__u32 path_fd;
	int fd;
};

SEC("syscall")
int sys_bpf_obj_get(struct obj_get_args *args)
{
	union bpf_attr attr = {};

	/* The ctx of a syscall program is in kernel memory while it runs */
	attr.pathname = (__u64)(long)args->path;
	attr.file_flags = args->file_flags;
	attr.path_fd = args->path_fd;
	args->fd = bpf_sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));

	return 0;
}

SEC("tc")
int sys_bpf_obj_get_target(struct __sk_buff *skb)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
