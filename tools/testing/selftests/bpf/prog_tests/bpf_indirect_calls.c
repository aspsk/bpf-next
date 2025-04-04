// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <test_progs.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "bpf_indirect_calls.skel.h"

static void __test_run(struct bpf_program *prog, void *ctx_in, size_t ctx_size_in)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
			    .ctx_in = ctx_in,
			    .ctx_size_in = ctx_size_in,
		   );
	int err, prog_fd;

	prog_fd = bpf_program__fd(prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run_opts err");
}

static void check_simple(struct bpf_indirect_calls *skel, __u64 ctx_in, __u64 expected)
{
	skel->bss->ret_user = 0;

	__test_run(skel->progs.simple_test, &ctx_in, sizeof(ctx_in));

	if (!ASSERT_EQ(skel->bss->ret_user, expected, "skel->bss->ret_user"))
		return;
}

static void check_calculon(struct bpf_indirect_calls *skel, const char *input, __u64 expected)
{
	int map_fd =  bpf_map__fd(skel->maps.calculon_input);
	__u64 n;
	__u32 i;

	n = strlen(input);
	for (i = 0; i < n; i++)
		bpf_map_update_elem(map_fd, &i, input + i, 0);

	skel->bss->ret_user = 0;

	__test_run(skel->progs.calculon, &n, sizeof(n));

	if (!ASSERT_EQ(skel->bss->ret_user, expected, "skel->bss->ret_user"))
		return;
}

void test_bpf_indirect_calls(void)
{
	struct bpf_indirect_calls *skel;

	skel = bpf_indirect_calls__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "aspsk_play__open_and_load"))
		return;

	if (test__start_subtest("check_simple")) {
		check_simple(skel, 1,  17 * 1);
		check_simple(skel, 2, 113 * 2);
		check_simple(skel, 3,  17 * 3);
		check_simple(skel, 4, 113 * 4);
	}

	if (test__start_subtest("check_calculon")) {
		check_calculon(skel, "1234567++++++", 28);
		check_calculon(skel, "2222222******", 128);
		check_calculon(skel, "34+6522*321+*+*+*222**16+39-41+4321+*+*+*+-3+", 11);
	}

	bpf_indirect_calls__destroy(skel);
}
