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

void test_run(int prog_fd)
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

	ASSERT_EQ(opts.retval, 0, "program returned non-zero");
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

	test_run(prog_fd);

	pause();

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

	pause();
	test_run(prog_fd);

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

	// test_run(prog_fd);

	pause();

	close(prog_fd);
	close(map_fd);
}

void test_bpf_goto_x(void)
{
	if (0 && test__start_subtest("basic_goto_x_1"))
		basic_goto_x_1();

	if (1 && test__start_subtest("basic_goto_x_2"))
		basic_goto_x_2();

	if (0 && test__start_subtest("goto_x_out_of_bounds"))
		goto_x_out_of_bounds();
}
