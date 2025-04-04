// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <linux/filter.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "cbpf_common.h"
#include "cbpf.skel.h"

static void run(struct cbpf *skel, __u8 *prog, __u32 prog_len, __u8 *packet, __u32 packet_len, int expected_ret)
{
	struct cbpf_test_input input =  {
		.prog_len = prog_len / 8,
		.packet_len = packet_len,
	};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
			    .ctx_in = &input,
			    .ctx_size_in = sizeof(input),
		   );
	int err, prog_fd;

	ASSERT_LE(packet_len, sizeof(skel->bss->packet), "packet_len");
	memcpy(skel->bss->packet, packet, packet_len);

	ASSERT_LE(prog_len, sizeof(skel->bss->prog), "prog_len");
	memcpy(skel->bss->prog, prog, prog_len);

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		return;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		return;

	ASSERT_EQ(skel->data->ret_value, expected_ret, "ret_value != expected_ret");
}

static void check1(struct cbpf *skel)
{
	struct cbpf_insn prog[] = {
		{ .opcode = BPF_LD | BPF_H | BPF_ABS, .k = 12 },                           /* (000) ldh      [12]				*/
		{ .opcode = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = 0x800 },     /* (001) jeq      #0x800           jt 2	jf 3	*/
		{ .opcode = BPF_RET | BPF_K, .k = 666 },                                   /* (002) ret      #666				*/
		{ .opcode = BPF_RET | BPF_K, .k = 0 },                                     /* (003) ret      #0					*/
	};
	__u8 ethernet_packet_ok[] = {
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x08, 0x00,		// Type
	};
	__u8 ethernet_packet_nok[] = {
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x07, 0x00,		// Type
	};

	run(skel, (void *)prog, sizeof(prog), ethernet_packet_ok, sizeof(ethernet_packet_ok), /*666 XXX*/ 0);
	run(skel, (void *)prog, sizeof(prog), ethernet_packet_nok, sizeof(ethernet_packet_nok), 0);
}

#if 0
static void test2()
{
	struct cbpf_insn prog[] = {
		{ .opcode = BPF_LD | BPF_H | BPF_ABS, .k = 12 },                           // (000) ldh      [12]
		{ .opcode = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 3, .k = 0x800 },     // (001) jeq      #0x800           jt 2	jf 5
		{ .opcode = BPF_LD | BPF_B | BPF_ABS, .k = 23 },                           // (002) ldb      [23]
		{ .opcode = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = 0x1 },       // (003) jeq      #0x1             jt 4	jf 5
		{ .opcode = BPF_RET | BPF_K, .k = 666 },                                   // (004) ret      #262144
		{ .opcode = BPF_RET | BPF_K, .k = 0 },                                     // (005) ret      #0
	};
	__u32 len = sizeof(prog) / sizeof(prog[0]);
	__u8 ethernet_packet_ok[] = {
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x08, 0x00,		// Type
		0,			// version + IHL
		0,			// TOS
		0, 0,			// length
		0, 0,			// id
		0, 0,			// flags, fo
		63, 1,			// TTL, Protocol
		0, 0,			// checksum
		0, 0, 0, 0,		// SIP
		0, 0, 0, 0,		// DIP
	};
	__u8 ethernet_packet_nok[] = {
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x08, 0x00,		// Type
		0,			// version + IHL
		0,			// TOS
		0, 0,			// length
		0, 0,			// id
		0, 0,			// flags, fo
		63, 2,			// TTL, Protocol [bad]
		0, 0,			// checksum
		0, 0, 0, 0,		// SIP
		0, 0, 0, 0,		// DIP
	};

	run("icmp-ok", ethernet_packet_ok, sizeof(ethernet_packet_ok), prog, len, 666);
	run("icmp-bad", ethernet_packet_nok, sizeof(ethernet_packet_nok), prog, len, 0);

}

static void test3()
{
	struct cbpf_insn prog[] = {
		{ 0x28,  0,  0, 0x0000000c },	// (000) ldh      [12]
		{ 0x15,  0,  2, 0x00000800 },	// (001) jeq      #0x800           jt 2	jf 4
		{ 0x30,  0,  0, 0x00000017 },	// (002) ldb      [23]
		{ 0x15,  6,  7, 0x00000006 },	// (003) jeq      #0x6             jt 10	jf 11
		{ 0x15,  0,  6, 0x000086dd },	// (004) jeq      #0x86dd          jt 5	jf 11
		{ 0x30,  0,  0, 0x00000014 },	// (005) ldb      [20]
		{ 0x15,  3,  0, 0x00000006 },	// (006) jeq      #0x6             jt 10	jf 7
		{ 0x15,  0,  3, 0x0000002c },	// (007) jeq      #0x2c            jt 8	jf 11
		{ 0x30,  0,  0, 0x00000036 },	// (008) ldb      [54]
		{ 0x15,  0,  1, 0x00000006 },	// (009) jeq      #0x6             jt 10	jf 11
		{ 0x06,  0,  0, 666 },       	// (010) ret      #262144
		{ 0x06,  0,  0, 0000000000 },	// (011) ret      #0
	};

	__u32 len = sizeof(prog) / sizeof(prog[0]);
	__u8 ethernet_packet_ok[] = {
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x08, 0x00,		// Type
		0,			// version + IHL
		0,			// TOS
		0, 0,			// length
		0, 0,			// id
		0, 0,			// flags, fo
		63, 6,			// TTL, Protocol
		0, 0,			// checksum
		0, 0, 0, 0,		// SIP
		0, 0, 0, 0,		// DIP
	};

	run("tcp-ok", ethernet_packet_ok, sizeof(ethernet_packet_ok), prog, len, 666);
}

static void test4()
{
	struct cbpf_insn prog[] = {
                 { 0x28,  0,  0, 0x0000000c }, // (000) ldh      [12]
                 { 0x15,  0,  8, 0x000086dd }, // (001) jeq      #0x86dd          jt 2____jf 10
                 { 0x30,  0,  0, 0x00000014 }, // (002) ldb      [20]
                 { 0x15,  2,  0, 0x00000084 }, // (003) jeq      #0x84            jt 6____jf 4
                 { 0x15,  1,  0, 0x00000006 }, // (004) jeq      #0x6             jt 6____jf 5
                 { 0x15,  0, 17, 0x00000011 }, // (005) jeq      #0x11            jt 6____jf 23
                 { 0x28,  0,  0, 0x00000036 }, // (006) ldh      [54]
                 { 0x15, 14,  0, 0x00000378 }, // (007) jeq      #0x378           jt 22___jf 8
                 { 0x28,  0,  0, 0x00000038 }, // (008) ldh      [56]
                 { 0x15, 12, 13, 0x00000378 }, // (009) jeq      #0x378           jt 22___jf 23
                 { 0x15,  0, 12, 0x00000800 }, // (010) jeq      #0x800           jt 11___jf 23
                 { 0x30,  0,  0, 0x00000017 }, // (011) ldb      [23]
                 { 0x15,  2,  0, 0x00000084 }, // (012) jeq      #0x84            jt 15___jf 13
                 { 0x15,  1,  0, 0x00000006 }, // (013) jeq      #0x6             jt 15___jf 14
                 { 0x15,  0,  8, 0x00000011 }, // (014) jeq      #0x11            jt 15___jf 23
                 { 0x28,  0,  0, 0x00000014 }, // (015) ldh      [20]
                 { 0x45,  6,  0, 0x00001fff }, // (016) jset     #0x1fff          jt 23___jf 17
                 { 0xb1,  0,  0, 0x0000000e }, // (017) ldxb     4*([14]&0xf)
                 { 0x48,  0,  0, 0x0000000e }, // (018) ldh      [x + 14]
                 { 0x15,  2,  0, 0x00000378 }, // (019) jeq      #0x378           jt 22___jf 20
                 { 0x48,  0,  0, 0x00000010 }, // (020) ldh      [x + 16]
                 { 0x15,  0,  1, 0x00000378 }, // (021) jeq      #0x378           jt 22___jf 23
                 { 0x06,  0,  0, 666 }, // (022) ret      #262144
                 { 0x06,  0,  0, 0000000000 }, // (023) ret      #0
	};

	__u32 len = sizeof(prog) / sizeof(prog[0]);
	__u8 ethernet_packet_ok[] = {
		// Ethernet
		0, 0, 0, 0, 0, 0,	// SRC MAC
		0, 0, 0, 0, 0, 0,	// DST MAC
		0x08, 0x00,		// Type
		// IPv4
		5 | (4 << 4),		// version + IHL
		0,			// TOS
		0, 0,			// length
		0, 0,			// id
		0, 0,			// flags, fo
		63, 0x11,		// TTL, Protocol
		0, 0,			// checksum
		0, 0, 0, 0,		// SIP
		0, 0, 0, 0,		// DIP
		// UDP
		1, 2,
		888 >> 8, 888 & 0xff,
	};

	run("tcp-ok", ethernet_packet_ok, sizeof(ethernet_packet_ok), prog, len, 666);
}
#endif

static void check(void)
{
	struct cbpf *skel;

	skel = cbpf__open_and_load();
	if (!ASSERT_NEQ(skel, NULL, "cbpf_open_and_load"))
		return;

	check1(skel);
	//check2(skel);
	//check3(skel);
	//check4(skel);

	cbpf__destroy(skel);
}

void test_cbpf(void)
{
	if (test__start_subtest("check"))
		check();
}
