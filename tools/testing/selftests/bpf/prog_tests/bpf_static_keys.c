// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <test_progs.h>
#include "bpf_static_keys.skel.h"

#define set_static_key(map_fd, val)						\
	do {									\
		__u32 map_value = (val);					\
		__u32 zero_key = 0;						\
		int ret;							\
										\
		ret = bpf_map_update_elem(map_fd, &zero_key, &map_value, 0);	\
		ASSERT_EQ(ret, 0, "bpf_map_update_elem");			\
	} while (0)

static void check_one_key(struct bpf_static_keys *skel)
{
	struct bpf_link *link;
	int map_fd;

	link = bpf_program__attach(skel->progs.check_one_key);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	map_fd = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd, 0, "skel->maps.key1");

	set_static_key(map_fd, 0);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 4, "skel->bss->ret_user");

	set_static_key(map_fd, 1);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 3, "skel->bss->ret_user");

	bpf_link__destroy(link);
}

static void check_multiple_progs(struct bpf_static_keys *skel)
{
	struct bpf_link *link1;
	struct bpf_link *link2;
	struct bpf_link *link3;
	int map_fd;

	link1 = bpf_program__attach(skel->progs.check_one_key);
	if (!ASSERT_OK_PTR(link1, "link1"))
		return;

	link2 = bpf_program__attach(skel->progs.check_one_key_another_prog);
	if (!ASSERT_OK_PTR(link2, "link2"))
		return;

	link3 = bpf_program__attach(skel->progs.check_one_key_yet_another_prog);
	if (!ASSERT_OK_PTR(link3, "link3"))
		return;

	map_fd = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd, 0, "skel->maps.key1");

	set_static_key(map_fd, 0);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 444, "skel->bss->ret_user");
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 888, "skel->bss->ret_user");

	set_static_key(map_fd, 1);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 333, "skel->bss->ret_user");
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 666, "skel->bss->ret_user");

	bpf_link__destroy(link3);
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
}

static void check_multiple_keys(struct bpf_static_keys *skel)
{
	struct bpf_link *link;
	int map_fd1;
	int map_fd2;
	int map_fd3;
	int i;

	link = bpf_program__attach(skel->progs.check_multiple_keys_unlikely);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	map_fd1 = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd1, 0, "skel->maps.key1");

	map_fd2 = bpf_map__fd(skel->maps.key2);
	ASSERT_GT(map_fd2, 0, "skel->maps.key2");

	map_fd3 = bpf_map__fd(skel->maps.key3);
	ASSERT_GT(map_fd3, 0, "skel->maps.key3");

	for (i = 0; i < 8; i++) {
		set_static_key(map_fd1, i & 1);
		set_static_key(map_fd2, i & 2);
		set_static_key(map_fd3, i & 4);

		usleep(1);
		ASSERT_EQ(skel->bss->ret_user, i, "skel->bss->ret_user");
	}

	bpf_link__destroy(link);
}

static void check_one_key_long_jump(struct bpf_static_keys *skel)
{
	struct bpf_link *link;
	int map_fd;

	link = bpf_program__attach(skel->progs.check_one_key_long_jump);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	map_fd = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd, 0, "skel->maps.key1");

	set_static_key(map_fd, 0);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 2256, "skel->bss->ret_user");

	set_static_key(map_fd, 1);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 1256, "skel->bss->ret_user");

	bpf_link__destroy(link);
}

static void check_bpf_to_bpf_call(struct bpf_static_keys *skel)
{
	struct bpf_link *link;
	int map_fd1;
	int map_fd2;

	link = bpf_program__attach(skel->progs.check_bpf_to_bpf_call);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	map_fd1 = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd1, 0, "skel->maps.key1");

	map_fd2 = bpf_map__fd(skel->maps.key2);
	ASSERT_GT(map_fd2, 0, "skel->maps.key2");

	set_static_key(map_fd1, 0);
	set_static_key(map_fd2, 0);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 0, "skel->bss->ret_user");

	set_static_key(map_fd1, 1);
	set_static_key(map_fd2, 0);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 101, "skel->bss->ret_user");

	set_static_key(map_fd1, 0);
	set_static_key(map_fd2, 1);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 1010, "skel->bss->ret_user");

	set_static_key(map_fd1, 1);
	set_static_key(map_fd2, 1);
	skel->bss->ret_user = 0;
	usleep(1);
	ASSERT_EQ(skel->bss->ret_user, 1111, "skel->bss->ret_user");


	bpf_link__destroy(link);
}

#define FIXED_MAP_FD 666

static void check_use_key_as_map(struct bpf_static_keys *skel)
{
	struct bpf_insn insns[] = {
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_LD_MAP_FD(BPF_REG_1, FIXED_MAP_FD),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
	};
	int map_fd;
	int ret;

	/* first check that prog loads ok */

	map_fd = bpf_map__fd(skel->maps.just_map);
	ASSERT_GT(map_fd, 0, "skel->maps.just_map");

	ret = dup2(map_fd, FIXED_MAP_FD);
	ASSERT_EQ(ret, FIXED_MAP_FD, "dup2");

	strncpy(attr.prog_name, "prog", sizeof(attr.prog_name));
	ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_GT(ret, 0, "BPF_PROG_LOAD");
	close(ret);
	close(FIXED_MAP_FD);

	/* now the incorrect map (static key as normal map) */

	map_fd = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(map_fd, 0, "skel->maps.key1");

	ret = dup2(map_fd, FIXED_MAP_FD);
	ASSERT_EQ(ret, FIXED_MAP_FD, "dup2");

	ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(ret, -1, "BPF_PROG_LOAD");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD");
	close(ret);
	close(FIXED_MAP_FD);
}

static void map_create_incorrect(void)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = 4,
		.value_size = 4,
		.max_entries = 1,
		.map_flags = BPF_F_STATIC_KEY,
	};
	int map_fd;

	/* The first call should be ok */

	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	ASSERT_GT(map_fd, 0, "BPF_MAP_CREATE");
	close(map_fd);

	/* All the rest calls should fail */

	attr.map_type = BPF_MAP_TYPE_HASH;
	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	ASSERT_EQ(map_fd, -1, "BPF_MAP_CREATE");
	attr.map_type = BPF_MAP_TYPE_ARRAY;

	attr.key_size = 8;
	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	ASSERT_EQ(map_fd, -1, "BPF_MAP_CREATE");
	attr.key_size = 4;

	attr.value_size = 8;
	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	ASSERT_EQ(map_fd, -1, "BPF_MAP_CREATE");
	attr.value_size = 4;

	attr.max_entries = 2;
	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	ASSERT_EQ(map_fd, -1, "BPF_MAP_CREATE");
	attr.max_entries = 1;
}

static void prog_load_incorrect_branches(struct bpf_static_keys *skel)
{
	int key_fd, map_fd, prog_fd;

	/*
	 *                 KEY=OFF               KEY=ON
	 * <prog>:
	 *        0:       r0 = 0x0              r0 = 0x0
	 *        1:       goto +0x0 <1>         goto +0x1 <2>
	 * <1>:
	 *        2:       exit                  exit
	 * <2>:
	 *        3:       r0 = 0x1              r0 = 0x1
	 *        4:       goto -0x3 <1>         goto -0x3 <1>
	 */
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, -3),
	};
	struct bpf_static_branch_info static_branches_info[] = {
		{
			.map_fd = -1,
			.insn_offset = 8,
			.jump_target = 24,
			.flags = 0,
		},
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.static_branches_info = ptr_to_u64(static_branches_info),
		.static_branches_info_size = sizeof(static_branches_info),
	};

	key_fd = bpf_map__fd(skel->maps.key1);
	ASSERT_GT(key_fd, 0, "skel->maps.key1");

	map_fd = bpf_map__fd(skel->maps.just_map);
	ASSERT_GT(map_fd, 0, "skel->maps.just_map");

	strncpy(attr.prog_name, "prog", sizeof(attr.prog_name));

	/* The first two loads should be ok, correct parameters */

	static_branches_info[0].map_fd = key_fd;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_GT(prog_fd, 0, "BPF_PROG_LOAD");
	close(prog_fd);

	static_branches_info[0].flags = BPF_F_INVERSE_BRANCH;
	insns[1] = BPF_JMP_IMM(BPF_JA, 0, 0, 1); /* inverse branch expects a nonzero offset */
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_GT(prog_fd, 0, "BPF_PROG_LOAD");
	close(prog_fd);
	static_branches_info[0].flags = 0;
	insns[1] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);

	/* All other loads should fail with -EINVAL */

	static_branches_info[0].map_fd = map_fd;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: incorrect map fd");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: incorrect map fd");
	static_branches_info[0].map_fd = key_fd;

	attr.static_branches_info = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: info is NULL, but size is not zero");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: info is NULL, but size is not zero");
	attr.static_branches_info = ptr_to_u64(static_branches_info);

	attr.static_branches_info_size = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: info is not NULL, but size is zero");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: info is not NULL, but size is zero");
	attr.static_branches_info_size = sizeof(static_branches_info);

	attr.static_branches_info_size = 1;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: size not divisible by item size");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: size not divisible by item size");
	attr.static_branches_info_size = sizeof(static_branches_info);

	static_branches_info[0].flags = 0xbeef;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: incorrect flags");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: incorrect flags");
	static_branches_info[0].flags = 0;

	static_branches_info[0].insn_offset = 1;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: incorrect insn_offset");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: incorrect insn_offset");
	static_branches_info[0].insn_offset = 8;

	static_branches_info[0].insn_offset = 64;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: insn_offset outside of prgoram");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: insn_offset outside of prgoram");
	static_branches_info[0].insn_offset = 8;

	static_branches_info[0].jump_target = 1;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: incorrect jump_target");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: incorrect jump_target");
	static_branches_info[0].jump_target = 8;

	static_branches_info[0].jump_target = 64;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: jump_target outside of prgoram");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: jump_target outside of prgoram");
	static_branches_info[0].jump_target = 8;

	static_branches_info[0].insn_offset = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	ASSERT_EQ(prog_fd, -1, "BPF_PROG_LOAD: patching not a JA");
	ASSERT_EQ(errno, EINVAL, "BPF_PROG_LOAD: patching not a JA");
	static_branches_info[0].insn_offset = 8;
}

void test_bpf_static_keys(void)
{
	struct bpf_static_keys *skel;

	skel = bpf_static_keys__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_static_keys__open_and_load"))
		return;

	if (test__start_subtest("check_one_key"))
		check_one_key(skel);

	if (test__start_subtest("check_multiple_keys"))
		check_multiple_keys(skel);

	if (test__start_subtest("check_multiple_progs"))
		check_multiple_progs(skel);

	if (test__start_subtest("check_one_key_long_jump"))
		check_one_key_long_jump(skel);

	if (test__start_subtest("check_bpf_to_bpf_call"))
		check_bpf_to_bpf_call(skel);

	/* Negative tests */

	if (test__start_subtest("check_use_key_as_map"))
		check_use_key_as_map(skel);

	if (test__start_subtest("map_create_incorrect"))
		map_create_incorrect();

	if (test__start_subtest("prog_load_incorrect_branches"))
		prog_load_incorrect_branches(skel);

	bpf_static_keys__destroy(skel);
}
