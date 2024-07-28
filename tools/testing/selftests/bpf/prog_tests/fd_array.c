// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <test_progs.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

static inline int _bpf_map_create(void)
{
	static union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = 4,
		.value_size = 8,
		.max_entries = 1,
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static bool map_exists(__u32 id)
{
	int fd;

	fd = bpf_map_get_fd_by_id(id);
	if (fd >= 0) {
		close(fd);
		return true;
	}
	return false;
}

static inline int bpf_prog_get_map_ids(int prog_fd, __u32 *nr_map_ids, __u32 *map_ids)
{
	__u32 len = sizeof(struct bpf_prog_info);
	struct bpf_prog_info info = {
		.nr_map_ids = *nr_map_ids,
		.map_ids = ptr_to_u64(map_ids),
	};
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd"))
		return -1;

	*nr_map_ids = info.nr_map_ids;

	return 0;
}

static int load_test_prog(int map_fd, int *fd_array, int fd_array_cnt)
{
	/* A trivial program which uses one map */
	struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(fd_array),
		.fd_array_cnt = fd_array_cnt,
	};

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static bool check_expected_map_ids(int prog_fd, int expected, __u32 *map_ids, __u32 *nr_map_ids)
{
	int err;

	err = bpf_prog_get_map_ids(prog_fd, nr_map_ids, map_ids);
	if (!ASSERT_OK(err, "bpf_prog_get_map_ids"))
		return false;
	if (!ASSERT_EQ(*nr_map_ids, expected, "unexpected nr_map_ids"))
		return false;

	return true;
}

static void check_fd_array(void)
{
	int extra_map_fds[8];
	__u32 map_ids[16];
	__u32 nr_map_ids;
	int prog_fd;
	int map_fd;

	map_fd = _bpf_map_create();
	if (!ASSERT_GE(map_fd, 0, "_bpf_map_create"))
		return;

	/* no extra maps, only one expected */
	prog_fd = load_test_prog(map_fd, NULL, 0);
	if (ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		return;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 1, map_ids, &nr_map_ids))
		return;
	close(prog_fd);

	/* two extra maps, no intersections, so three expected */
	extra_map_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_map_fds[0], 0, "_bpf_map_create"))
		return;
	extra_map_fds[1] = _bpf_map_create();
	if (!ASSERT_GE(extra_map_fds[1], 0, "_bpf_map_create"))
		return;
	prog_fd = load_test_prog(map_fd, extra_map_fds, 2);
	if (ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		return;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 3, map_ids, &nr_map_ids))
		return;

	/* maps should still exist when file descriptors are closed */
	close(extra_map_fds[0]);
	close(extra_map_fds[1]);
	if (!map_exists(map_ids[0]))
		return;
	if (!map_exists(map_ids[1]))
		return;
	close(prog_fd);
	if (!map_exists(map_ids[0]))
		return;
	if (!map_exists(map_ids[1]))
		return;

	/*
	 * The same test as above repeated, but maps are duplicated
	 * they should be only referenced once after the load
	 */
	extra_map_fds[0] = extra_map_fds[2] = _bpf_map_create();
	if (!ASSERT_GE(extra_map_fds[0], 0, "_bpf_map_create"))
		return;
	extra_map_fds[1] = extra_map_fds[3] = _bpf_map_create();
	if (!ASSERT_GE(extra_map_fds[1], 0, "_bpf_map_create"))
		return;
	prog_fd = load_test_prog(map_fd, extra_map_fds, 4);
	if (ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		return;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 3, map_ids, &nr_map_ids))
		return;

	/* maps should still exist when file descriptors are closed */
	close(extra_map_fds[0]);
	close(extra_map_fds[1]);
	if (!map_exists(map_ids[0]))
		return;
	if (!map_exists(map_ids[1]))
		return;
	close(prog_fd);
	if (!map_exists(map_ids[0]))
		return;
	if (!map_exists(map_ids[1]))
		return;

	/*
	 * Check that if maps which are referenced by the program are passed
	 * in bind_fd_array, then they will be referenced only once
	 */
	extra_map_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_map_fds[0], 0, "_bpf_map_create"))
		return;
	prog_fd = load_test_prog(extra_map_fds[0], extra_map_fds, 1);
	if (ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		return;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 1, map_ids, &nr_map_ids))
		return;
	/* maps should still exist when file descriptors are closed */
	close(extra_map_fds[0]);
	if (!map_exists(map_ids[0]))
		return;
	close(prog_fd);
	if (map_exists(map_ids[0]))
		return;

	// XXX check that we can't load a program with trash sent in bind_fd_array
	// XXX check that we can't load a program with non-map fds sent in bind_fd_array

	close(map_fd);
}

void test_prog_load_fd_array(void)
{
	if (test__start_subtest("fd_array"))
		check_fd_array();
}
