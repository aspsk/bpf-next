// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
/* Copyright (c) 2025 Isovalent */
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include "test_xdp_link.skel.h"
// doesn't work as it also includes tc skeleton #include "tc_helpers.h" // XXX xdp

#define IFINDEX_LO 1
#define PING_CMD "ping -q -c1 -w1 127.0.0.1 > /dev/null"

static inline void reset_all_seen(struct test_xdp_link *skel)
{
	memset(skel->bss, 0, sizeof(*skel->bss));
}

static inline __u32 ifindex_from_link_fd(int fd)
{
	struct bpf_link_info link_info = {};
	__u32 link_info_len = sizeof(link_info);
	int err;

	err = bpf_link_get_info_by_fd(fd, &link_info, &link_info_len);
	if (!ASSERT_OK(err, "id_from_link_fd"))
		return 0;

	return link_info.xdp.ifindex;
}

static inline void __assert_mprog_count(int target, int expected, int ifindex)
{
	__u32 count = 0, attach_flags = 0;
	int err;

	err = bpf_prog_query(ifindex, target, 0, &attach_flags, NULL, &count);
	ASSERT_EQ(count, expected, "count");
	ASSERT_EQ(err, 0, "prog_query");
}

static inline void assert_mprog_count(int target, int expected)
{
	__assert_mprog_count(target, expected, IFINDEX_LO);
}

static inline void assert_mprog_count_ifindex(int ifindex, int target, int expected)
{
	__assert_mprog_count(target, expected, ifindex);
}

void serial_test_xdp_link(void)
{
	struct test_xdp_link *skel1 = NULL, *skel2 = NULL;
	__u32 id1, id2, id0 = 0, prog_fd1, prog_fd2;
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	struct bpf_link_info link_info;
	struct bpf_prog_info prog_info;
	struct bpf_link *link;
	int err;
	__u32 link_info_len = sizeof(link_info);
	__u32 prog_info_len = sizeof(prog_info);

	skel1 = test_xdp_link__open_and_load();
	if (!ASSERT_OK_PTR(skel1, "skel_load"))
		goto cleanup;
	prog_fd1 = bpf_program__fd(skel1->progs.xdp_handler);

	skel2 = test_xdp_link__open_and_load();
	if (!ASSERT_OK_PTR(skel2, "skel_load"))
		goto cleanup;
	prog_fd2 = bpf_program__fd(skel2->progs.xdp_handler);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_prog_get_info_by_fd(prog_fd1, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info1"))
		goto cleanup;
	id1 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_prog_get_info_by_fd(prog_fd2, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info2"))
		goto cleanup;
	id2 = prog_info.id;

	/* set initial prog attachment */
	err = bpf_xdp_attach(IFINDEX_LO, prog_fd1, XDP_FLAGS_REPLACE, &opts);
	if (!ASSERT_OK(err, "fd_attach"))
		goto cleanup;

	/* validate prog ID */
	err = bpf_xdp_query_id(IFINDEX_LO, 0, &id0);
	if (!ASSERT_OK(err, "id1_check_err") || !ASSERT_EQ(id0, id1, "id1_check_val"))
		goto cleanup;

	/* BPF link is not allowed to replace prog attachment */
	link = bpf_program__attach_xdp(skel1->progs.xdp_handler, IFINDEX_LO);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		/* best-effort detach prog */
		opts.old_prog_fd = prog_fd1;
		bpf_xdp_detach(IFINDEX_LO, XDP_FLAGS_REPLACE, &opts);
		goto cleanup;
	}

	/* detach BPF program */
	opts.old_prog_fd = prog_fd1;
	err = bpf_xdp_detach(IFINDEX_LO, XDP_FLAGS_REPLACE, &opts);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup;

	/* now BPF link should attach successfully */
	link = bpf_program__attach_xdp(skel1->progs.xdp_handler, IFINDEX_LO);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel1->links.xdp_handler = link;

	/* validate prog ID */
	err = bpf_xdp_query_id(IFINDEX_LO, 0, &id0);
	if (!ASSERT_OK(err, "id1_check_err") || !ASSERT_EQ(id0, id1, "id1_check_val"))
		goto cleanup;

	/* BPF prog attach is not allowed to replace BPF link */
	opts.old_prog_fd = prog_fd1;
	err = bpf_xdp_attach(IFINDEX_LO, prog_fd2, XDP_FLAGS_REPLACE, &opts);
	if (!ASSERT_ERR(err, "prog_attach_fail"))
		goto cleanup;

	/* Can't force-update when BPF link is active */
	err = bpf_xdp_attach(IFINDEX_LO, prog_fd2, 0, NULL);
	if (!ASSERT_ERR(err, "prog_update_fail"))
		goto cleanup;

	/* Can't force-detach when BPF link is active */
	err = bpf_xdp_detach(IFINDEX_LO, 0, NULL);
	if (!ASSERT_ERR(err, "prog_detach_fail"))
		goto cleanup;

	/* BPF link is not allowed to replace another BPF link */
	link = bpf_program__attach_xdp(skel2->progs.xdp_handler, IFINDEX_LO);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	bpf_link__destroy(skel1->links.xdp_handler);
	skel1->links.xdp_handler = NULL;

	/* new link attach should succeed */
	link = bpf_program__attach_xdp(skel2->progs.xdp_handler, IFINDEX_LO);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel2->links.xdp_handler = link;

	err = bpf_xdp_query_id(IFINDEX_LO, 0, &id0);
	if (!ASSERT_OK(err, "id2_check_err") || !ASSERT_EQ(id0, id2, "id2_check_val"))
		goto cleanup;

	/* updating program under active BPF link works as expected */
	err = bpf_link__update_program(link, skel1->progs.xdp_handler);
	if (!ASSERT_OK(err, "link_upd"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_link_get_info_by_fd(bpf_link__fd(link),
				      &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_XDP, "link_type");
	ASSERT_EQ(link_info.prog_id, id1, "link_prog_id");
	ASSERT_EQ(link_info.xdp.ifindex, IFINDEX_LO, "link_ifindex");

	/* updating program under active BPF link with different type fails */
	err = bpf_link__update_program(link, skel1->progs.tc_handler);
	if (!ASSERT_ERR(err, "link_upd_invalid"))
		goto cleanup;

	err = bpf_link__detach(link);
	if (!ASSERT_OK(err, "link_detach"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_link_get_info_by_fd(bpf_link__fd(link),
				      &link_info, &link_info_len);

	ASSERT_OK(err, "link_info");
	ASSERT_EQ(link_info.prog_id, id1, "link_prog_id");
	/* ifindex should be zeroed out */
	ASSERT_EQ(link_info.xdp.ifindex, 0, "link_ifindex");

cleanup:
	test_xdp_link__destroy(skel1);
	test_xdp_link__destroy(skel2);
}

void serial_test_xdp_mprog_basic(void)
{
	LIBBPF_OPTS(bpf_prog_query_opts, optq);
	LIBBPF_OPTS(bpf_xdp_opts, optl);
	__u32 prog_ids[2], link_ids[2];
	__u32 pid1, pid2, lid1, lid2;
	struct test_xdp_link *skel;
	struct bpf_link *link;
	int err;

	skel = test_xdp_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	pid1 = id_from_prog_fd(bpf_program__fd(skel->progs.xdp_ingress1));
	pid2 = id_from_prog_fd(bpf_program__fd(skel->progs.xdp_ingress2));

	ASSERT_NEQ(pid1, pid2, "prog_ids_1_2");

	assert_mprog_count(BPF_XDP_INGRESS, 0);
	assert_mprog_count(BPF_XDP_EGRESS, 0);

	ASSERT_EQ(skel->bss->seen_xdp_ingress1, false, "seen_xdp_ingress1");
	ASSERT_EQ(skel->bss->seen_xdp_ingress2, false, "seen_xdp_ingress2");

	link = bpf_program__attach_xdp_opts(skel->progs.xdp_ingress1, IFINDEX_LO, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.xdp_ingress1 = link;

	lid1 = id_from_link_fd(bpf_link__fd(skel->links.xdp_ingress1));

	assert_mprog_count(BPF_XDP_INGRESS, 1);
	assert_mprog_count(BPF_XDP_EGRESS, 0);

	optq.prog_ids = prog_ids;
	optq.link_ids = link_ids;

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(IFINDEX_LO, BPF_XDP_INGRESS, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 1, "count");
	ASSERT_EQ(optq.revision, 2, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], 0, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], 0, "link_ids[1]");

	reset_all_seen(skel);
	ASSERT_OK(system(PING_CMD), PING_CMD);
	ASSERT_EQ(skel->bss->seen_xdp_ingress1, true, "seen_xdp_ingress1");
	ASSERT_EQ(skel->bss->seen_xdp_ingress2, false, "seen_xdp_ingress2");

	link = bpf_program__attach_xdp_opts(skel->progs.xdp_ingress2, IFINDEX_LO, &optl);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	skel->links.xdp_ingress2 = link;

	lid2 = id_from_link_fd(bpf_link__fd(skel->links.xdp_ingress2));
	ASSERT_NEQ(lid1, lid2, "link_ids_1_2");

	assert_mprog_count(BPF_XDP_INGRESS, 2);
	assert_mprog_count(BPF_XDP_EGRESS, 0);

	memset(prog_ids, 0, sizeof(prog_ids));
	memset(link_ids, 0, sizeof(link_ids));
	optq.count = ARRAY_SIZE(prog_ids);

	err = bpf_prog_query_opts(IFINDEX_LO, BPF_XDP_INGRESS, &optq);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(optq.count, 2, "count");
	ASSERT_EQ(optq.revision, 3, "revision");
	ASSERT_EQ(optq.prog_ids[0], pid1, "prog_ids[0]");
	ASSERT_EQ(optq.link_ids[0], lid1, "link_ids[0]");
	ASSERT_EQ(optq.prog_ids[1], pid2, "prog_ids[1]");
	ASSERT_EQ(optq.link_ids[1], lid2, "link_ids[1]");

	reset_all_seen(skel);
	ASSERT_OK(system(PING_CMD), PING_CMD);

	ASSERT_EQ(skel->bss->seen_xdp_ingress1, true, "seen_xdp_ingress1");
	ASSERT_EQ(skel->bss->seen_xdp_ingress2, true, "seen_xdp_ingress2");

cleanup:
	test_xdp_link__destroy(skel);

	assert_mprog_count(BPF_TCX_INGRESS, 0);
	assert_mprog_count(BPF_TCX_EGRESS, 0);
}
