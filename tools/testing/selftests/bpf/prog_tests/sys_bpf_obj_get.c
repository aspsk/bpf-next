// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include "sys_bpf_obj_get.skel.h"

#define PIN_PATH "/sys/fs/bpf/sys_bpf_obj_get_target"
#define NOENT_PATH "/sys/fs/bpf/sys_bpf_obj_get_noent"

struct obj_get_args {
	char path[PATH_MAX];
	__u32 file_flags;
	__u32 path_fd;
	int fd;
};

static int run_obj_get(struct sys_bpf_obj_get *skel, const char *path, __u32 file_flags,
		       __u32 path_fd, int *fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct obj_get_args args = {};
	int err;

	strncpy(args.path, path, sizeof(args.path) - 1);
	args.file_flags = file_flags;
	args.path_fd = path_fd;
	topts.ctx_in = &args;
	topts.ctx_size_in = sizeof(args);

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.sys_bpf_obj_get), &topts);
	*fd = args.fd;
	return err;
}

static __u32 prog_id(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len))
		return 0;
	return info.id;
}

/* The pin path, with leading slashes up to len characters */
static void pad_path(char *path, size_t len)
{
	size_t n = strlen(PIN_PATH);

	memset(path, '/', len - n);
	strcpy(path + len - n, PIN_PATH);
}

/* A syscall program opens a program pinned by the test, and gets the same program */
static void check_prog(struct sys_bpf_obj_get *skel, const char *path)
{
	int tgt_fd, fd, err;

	tgt_fd = bpf_program__fd(skel->progs.sys_bpf_obj_get_target);
	unlink(PIN_PATH);
	if (!ASSERT_OK(bpf_obj_pin(tgt_fd, PIN_PATH), "bpf_obj_pin"))
		return;

	err = run_obj_get(skel, path, 0, 0, &fd);
	if (!ASSERT_OK(err, "run_obj_get"))
		goto cleanup;

	if (ASSERT_GE(fd, 0, "BPF_OBJ_GET")) {
		__u32 id = prog_id(fd);
		__u32 tgt_id = prog_id(tgt_fd);

		ASSERT_NEQ(id, 0, "prog_id");
		ASSERT_EQ(id, tgt_id, "prog_id == tgt_id");
		close(fd);
	}

cleanup:
	unlink(PIN_PATH);
}

static void check_err(struct sys_bpf_obj_get *skel, const char *path, __u32 file_flags,
		      int expected)
{
	int fd, err;

	err = run_obj_get(skel, path, file_flags, 0, &fd);
	if (!ASSERT_OK(err, "run_obj_get"))
		return;

	ASSERT_EQ(fd, expected, "BPF_OBJ_GET");
	if (fd >= 0)
		close(fd);
}

void test_sys_bpf_obj_get(void)
{
	struct sys_bpf_obj_get *skel;
	char path[PATH_MAX];

	skel = sys_bpf_obj_get__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sys_bpf_obj_get__open_and_load"))
		return;

	if (test__start_subtest("prog"))
		check_prog(skel, PIN_PATH);
	/* A kernel path is one character shorter than a user one, see bpf_obj_lookup() */
	if (test__start_subtest("long")) {
		pad_path(path, PATH_MAX - 2);
		check_prog(skel, path);
	}
	if (test__start_subtest("too-long")) {
		pad_path(path, PATH_MAX - 1);
		check_err(skel, path, 0, -ENAMETOOLONG);
	}
	if (test__start_subtest("empty"))
		check_err(skel, "", 0, -ENOENT);
	/* Kernel callers can't pass a directory fd */
	if (test__start_subtest("path-fd"))
		check_err(skel, PIN_PATH, BPF_F_PATH_FD, -EINVAL);
	if (test__start_subtest("noent"))
		check_err(skel, NOENT_PATH, 0, -ENOENT);

	sys_bpf_obj_get__destroy(skel);
}
