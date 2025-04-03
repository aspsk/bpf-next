// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <test_progs.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "bpf_goto_x.skel.h"

static inline int _bpf_insn_set_create(__u32 *offsets, size_t n)
{
	static union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_INSN_SET,
		.key_size = 4,
		.value_size = 4,
		.max_entries = 0,
	};
	int map_fd;
	int ret;
	__u32 i;

	attr.max_entries = n;

	map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (map_fd < 0)
		return map_fd;

	for (i = 0; i < n; i++) {
		ret = bpf_map_update_elem(map_fd, &i, &offsets[i], 0);
		if (ret) {
			close(map_fd);
			return ret;
		}
	}

	bpf_map_freeze(map_fd);

	return map_fd;
}

static char log[65536];

static inline int _bpf_prog_load(struct bpf_insn *insns, __u32 insn_cnt)
{
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = insn_cnt,
		.log_level = 2,
		.log_size = sizeof(log),
		.log_buf = (__u64)(long)log,
		.license   = ptr_to_u64("GPL"),
	};

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

#define BPF_GOTO_X(Rx, FLAGS)				\
	((struct bpf_insn) {				\
		.code  = BPF_JMP | BPF_JA | BPF_X,	\
		.dst_reg = 0,				\
		.src_reg = Rx,				\
		.off   = 0,				\
		.imm   = 0 }) /* to be replaced with the actual fd before the load */

struct udp_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[64 - sizeof(struct udphdr) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __attribute__((__packed__));

static struct udp_packet pkt_udp = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = bpf_htons(sizeof(struct udp_packet) - offsetof(struct udp_packet, udp)),
	.iph.hop_limit = 1,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.udp.source = bpf_htons(1),
	.udp.dest = bpf_htons(1),
	.udp.len = bpf_htons(sizeof(struct udp_packet) - offsetof(struct udp_packet, udp)),
};

#define PKT_SIZE (sizeof(pkt_udp))

void test_run(int prog_fd, int expected_retval)
{
	struct xdp_md ctx_in = { .data_end = PKT_SIZE, };
	DECLARE_LIBBPF_OPTS(
		bpf_test_run_opts, opts,
		.data_in = &pkt_udp,
		.data_size_in = PKT_SIZE,
		.ctx_in = &ctx_in,
		.ctx_size_in = sizeof(ctx_in),
		.repeat = 1,
	);
	int ret;

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_EQ(ret, 0, "bpf_prog_test_run_opts program"))
		return;

	ASSERT_EQ(opts.retval, expected_retval, "retval != expected_retval");
}

static void basic_goto_x_1(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_1, 0),		/* 0: R1 = 0 */
		BPF_GOTO_X(1, 0),			/* 1: goto M[R1], M={2} */
		BPF_MOV64_IMM(BPF_REG_0, XDP_PASS),	/* 2: R0 = XDP_PASS */
		BPF_EXIT_INSN(),			/* 3: exit */
	};
	__u32 offsets[] = { 2 };
	int prog_fd;
	int map_fd;

	map_fd = _bpf_insn_set_create(offsets, 1);
	if (!ASSERT_GE(map_fd, 0, "map is ok"))
		return;

	/* set the correct map fd */
	insns[1].imm = map_fd; // 1 is hardcoded

	prog_fd = _bpf_prog_load(insns, ARRAY_SIZE(insns));
	if (!ASSERT_GE(prog_fd, 0, "correct program")) {
		write(2, log, sizeof(log));
		return;
	}

	pause();

	test_run(prog_fd, XDP_PASS);

	close(prog_fd);
	close(map_fd);
}

	static void basic_goto_x_2(void)
	{


		__u8 _insns[] = {
	/*start:*/
			0x85, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // call 0x7
			0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r6 = r0
	/*repeat:*/
			0xbf, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = r6
			0x57, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // r2 &= 0x1
			0x0d, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // goto r2
	/*null:*/
			0x85, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // call 0x7
			0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // goto +0x2 <cont>

	/*eis:*/
			0x85, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // call 0x7
			0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // goto +0x0 <cont>
	/*cont:*/
			0x15, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // if r6 == 0x0 goto +0x3 <end>
			0x77, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // r6 >>= 0x1
			0xe5, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // may_goto +1
			0x05, 0x00, 0xf5, 0xff, 0x00, 0x00, 0x00, 0x00, // goto -0xb <repeat>

	/*end:*/
			0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // r0 = 0x2
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
		};



	struct bpf_insn *insns = (struct bpf_insn *)_insns;
	__u32 offsets[] = { 5, 7 };
	int prog_fd;
	int map_fd;

	map_fd = _bpf_insn_set_create(offsets, 2);
	if (!ASSERT_GE(map_fd, 0, "map is ok"))
		return;

	/* set the correct map fd */
	insns[4].imm = map_fd; // 3 is hardcoded

	prog_fd = _bpf_prog_load(insns, ARRAY_SIZE(_insns) / 8);
	if (!ASSERT_GE(prog_fd, 0, "correct program")) {
		write(2, log, sizeof(log));
		return;
	}

	//pause();
	test_run(prog_fd, XDP_PASS);

	close(prog_fd);
	close(map_fd);
}

static void goto_x_out_of_bounds(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_1, 100),		// 0: R1 = 100, out of bounds
		BPF_GOTO_X(1, 0),			// 1: goto M[R1], M={2}
		BPF_MOV64_IMM(BPF_REG_0, XDP_PASS),	// 2: R0 = XDP_PASS
		BPF_EXIT_INSN(),			// 3: exit
	};
	__u32 offsets[] = { 2 };
	int prog_fd;
	int map_fd;

	map_fd = _bpf_insn_set_create(offsets, 1);
	if (!ASSERT_GE(map_fd, 0, "map is ok"))
		return;

	/* set the correct map fd */
	insns[1].imm = map_fd; // 1 is hardcoded

	prog_fd = _bpf_prog_load(insns, ARRAY_SIZE(insns));
	if (!ASSERT_EQ(prog_fd, 0, "incorrect program should have been rejected")) {
		write(2, log, sizeof(log));
		return;
	}

	close(prog_fd);
	close(map_fd);
}

static int setup_skel_tbd(struct bpf_goto_x *skel)
{
	struct bpf_insn *insns;
	int map_fd;
	__u32 offsets[] = {
		8,     /* 18 01 00 00 28 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x28 ll */
		36,    /* 18 01 00 00 2d 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x2d ll */
		22,    /* 18 01 00 00 32 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x32 ll */
		29,    /* 18 01 00 00 37 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x37 ll */
		15,    /* 18 01 00 00 3c 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x3c ll */
	};

	map_fd = _bpf_insn_set_create(offsets, ARRAY_SIZE(offsets));
	if (!ASSERT_GE(map_fd, 0, "map is ok"))
		return -1;

	insns = (struct bpf_insn *)bpf_program__insns(skel->progs.simple_test);

	// but how I can tell libbpf not to rewrite the map here?!
	insns[3].src_reg = 2;
	insns[3].imm = map_fd;

	/* put same map_fd into gotox */
	insns[7].imm = map_fd;

	return 0;
}

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

static void check_simple(struct bpf_goto_x *skel, __u64 ctx_in, __u64 expected)
{
	skel->bss->ret_user = 0;

	//pause();

	__test_run(skel->progs.simple_test, &ctx_in, sizeof(ctx_in));

	if (!ASSERT_EQ(skel->bss->ret_user, expected, "skel->bss->ret_user"))
		return;
}


static void check_skel_tbd(struct bpf_goto_x *skel)
{
	check_simple(skel, 0, 2);
	check_simple(skel, 1, 3);
	check_simple(skel, 2, 4);
	check_simple(skel, 3, 5);
	check_simple(skel, 4, 7);
	check_simple(skel, 5, 19);
	check_simple(skel, 77, 19);
}

void goto_x_skel(void)
{
	struct bpf_goto_x *skel;
	int ret;

	skel = bpf_goto_x__open();
	if (!ASSERT_NEQ(skel, NULL, "bpf_goto_x__open"))
		return;

	ret = setup_skel_tbd(skel);
	if (!ASSERT_OK(ret, "setup_skel_tbd"))
		return;

	ret = bpf_goto_x__load(skel);
	if (!ASSERT_OK(ret, "bpf_goto_x__load"))
		return;

	check_skel_tbd(skel);

	bpf_goto_x__destroy(skel);
}

void test_bpf_goto_x(void)
{
	if (0 && test__start_subtest("basic_goto_x_1"))
		basic_goto_x_1();

	if (0 && test__start_subtest("basic_goto_x_2"))
		basic_goto_x_2();

	if (0 && test__start_subtest("goto_x_out_of_bounds"))
		goto_x_out_of_bounds();

	if (1 && test__start_subtest("goto_x_skel"))
		goto_x_skel();
}
