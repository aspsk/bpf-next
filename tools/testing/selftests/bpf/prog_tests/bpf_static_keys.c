// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

#define VAL_ON	7
#define VAL_OFF	3

enum {
	OFF,
	ON
};

static int _bpf_prog_load(struct bpf_insn *insns, __u32 insn_cnt)
{
	return bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, NULL);
}

static int _bpf_static_key_update(int map_fd, __u32 on)
{
	LIBBPF_OPTS(bpf_static_key_update_opts, opts);

	opts.on = on;

	return bpf_static_key_update(map_fd, &opts);
}

#define BPF_JMP32_OR_NOP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_JMP_OR_NOP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_NOP_OR_JMP32(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA |		\
			   BPF_STATIC_BRANCH_NOP,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_NOP_OR_JMP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA |		\
			   BPF_STATIC_BRANCH_NOP,		\
		.off   = OFF,					\
		.imm   = IMM })

static const struct bpf_insn insns0[] = {
	BPF_JMP_OR_NOP(0, 1),
	BPF_NOP_OR_JMP(0, 1),
	BPF_JMP32_OR_NOP(1, 0),
	BPF_NOP_OR_JMP32(1, 0),
};

/* Lower-level selftests for the gotol_or_nop/nop_or_gotol instructions */
static void check_insn(void)
{
	struct bpf_insn insns[] = {
		{}, /* we will substitute this by insn0[i], i=0,1,2,3 */
		BPF_JMP_IMM(BPF_JA, 0, 0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, -2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	bool stop = false;
	int prog_fd[4];
	int i;

	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_GE(prog_fd[i], 0, "correct program"))
			stop = true;
	}

	for (i = 0; i < 4; i++)
		close(prog_fd[i]);

	if (stop)
		return;

	/* load should fail: incorrect SRC */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].src_reg |= 4;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect src"))
			return;
	}

	/* load should fail: incorrect DST */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].dst_reg = i + 1; /* non-zero */
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect dst"))
			return;
	}

	/* load should fail: both off and imm are set */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].imm = insns[0].off = insns0[i].imm ?: insns0[i].off;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;
	}

	/* load should fail: offset is incorrect */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];

		if (insns0[i].imm)
			insns[0].imm = -2;
		else
			insns[0].off = -2;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;

		if (insns0[i].imm)
			insns[0].imm = 42;
		else
			insns[0].off = 42;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;

		/* 0 is not allowed */
		insns[0].imm = insns[0].off = 0;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;
	}

	/* incorrect field is used */
	for (i = 0; i < 4; i++) {
		int tmp;

		insns[0] = insns0[i];

		tmp = insns[0].imm;
		insns[0].imm = insns[0].off;
		insns[0].off = tmp;

		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect field"))
			return;
	}
}

void test_bpf_static_keys(void)
{
	if (test__start_subtest("check_insn"))
		check_insn();
}
