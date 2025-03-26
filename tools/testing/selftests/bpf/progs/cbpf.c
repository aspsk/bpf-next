#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"

#include "cbpf_common.h"

#define debug(...) do {} while(0)

#define EINVAL -22

#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

#define		BPF_RET		0x06
#define		BPF_K		0x00
#define		BPF_X		0x08
#define		BPF_A		0x10

#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08


struct cbpf_state {
	__u32 A;
	__u32 X;
	__u32 M[16];
	__u32 pc;
	__u32 ret_value;
	const __u8 *packet;
	__u32 packet_len;
};

#define BPF_INSN_MAP(INSN_1, INSN_2, INSN_3) 	\
		INSN_1(ST),			\
		INSN_1(STX),			\
		INSN_2(JMP, JA),		\
		INSN_2(RET, A),			\
		INSN_2(RET, K),			\
		INSN_2(MISC, TAX),		\
		INSN_2(MISC, TXA),		\
		INSN_2(LD, MEM),		\
		INSN_2(LD, IMM),		\
		INSN_2(LDX, IMM),		\
		INSN_2(LDX, MEM),		\
		INSN_3(ALU, ADD, X),		\
		INSN_3(ALU, ADD, K),		\
		INSN_3(ALU, SUB, X),		\
		INSN_3(ALU, SUB, K),		\
		INSN_3(ALU, MUL, X),		\
		INSN_3(ALU, MUL, K),		\
		INSN_3(ALU, DIV, X),		\
		INSN_3(ALU, DIV, K),		\
		INSN_3(ALU, AND, X),		\
		INSN_3(ALU, AND, K),		\
		INSN_3(ALU, OR, X),		\
		INSN_3(ALU, OR, K),		\
		INSN_3(ALU, LSH, X),		\
		INSN_3(ALU, LSH, K),		\
		INSN_3(ALU, RSH, X),		\
		INSN_3(ALU, RSH, K),		\
		INSN_3(JMP, JEQ, K),		\
		INSN_3(JMP, JSET, K),		\
		INSN_3(JMP, JGT, K),		\
		INSN_3(JMP, JGE, K),		\
		INSN_3(LD, B, ABS),		\
		INSN_3(LD, H, ABS),		\
		INSN_3(LD, W, ABS),		\
		INSN_3(LD, B, IND),		\
		INSN_3(LD, H, IND),		\
		INSN_3(LD, W, IND),		\
		INSN_3(LD, W, LEN),		\
		INSN_3(LDX, W, LEN),		\
		INSN_3(LDX, MSH, B)

static inline __u32 read_u32(const __u8 *ctx, __u32 off)
{
	__u32 tmp;

	__builtin_memcpy(&tmp, ctx + off, 4);

	return bpf_ntohl(tmp);
}

static __u16 read_u16(const __u8 *ctx, __u32 off)
{
	__u16 tmp;

	__builtin_memcpy(&tmp, ctx + off, 2);

	return bpf_ntohs(tmp);
}

static __u8 read_u8(const __u8 *ctx, __u32 off)
{
	return ctx[off];
}

int ret_value = -1;

int zero = 0;

struct cbpf_insn prog[BPF_MAXINSNS];
__u8 packet[1024];

__noinline
int cbpf_update_state(volatile struct cbpf_state *state __arg_nonnull,
		      __u32 len,
		      __u32 *insn_idx __arg_nonnull)
{
	const struct cbpf_insn *insn;
	int d;

	if (len > 4)
		return -EINVAL;

	if (*insn_idx >= len)
		return -EINVAL;

	insn = &prog[*insn_idx];

#define LABEL_1(x)       x##_label
#define LABEL_2(x, y)    x##_##y##_label
#define LABEL_3(x, y, z) x##_##y##_##z##_label

#define BPF_INSN_1_LBL(x)       [BPF_##x] = &&LABEL_1(x)
#define BPF_INSN_2_LBL(x, y)    [BPF_##x | BPF_##y] = &&LABEL_2(x, y)
#define BPF_INSN_3_LBL(x, y, z) [BPF_##x | BPF_##y | BPF_##z] = &&LABEL_3(x, y, z)

	static const void *const jumptable[256] = {
		[0 ... 255] = &&default_label,
		BPF_INSN_MAP(BPF_INSN_1_LBL, BPF_INSN_2_LBL, BPF_INSN_3_LBL),
	};

#undef BPF_INSN_3_LBL
#undef BPF_INSN_2_LBL
#undef BPF_INSN_1_LBL

#define CONT ({ insn++; goto select_insn; })

select_insn:
	goto *jumptable[insn->opcode];

LABEL_2(RET, A):
	debug("ret %d\n", state->A);
	state->ret_value = state->A;
	return 0;

LABEL_2(RET, K):
	debug("ret %d\n", insn->k);
	state->ret_value = insn->k;
	return 0;

#define TBD goto default_label

LABEL_1(ST):
	TBD;

LABEL_1(STX):
	TBD;

LABEL_2(JMP, JA):
	TBD;
LABEL_3(JMP, JEQ, K):
	debug("jeq (A=0x%08x, K=0x%08x)\n", state->A, insn->k); // XXX: why don't I check that we're out of bounds?
	insn += state->A == insn->k ? insn->jt : insn->jf;
	CONT;
LABEL_3(JMP, JSET, K):
	debug("jset (A=0x%08x, K=0x%08x)\n", state->A, insn->k);
	insn += (state->A & insn->k) ? insn->jt : insn->jf;
	CONT;
LABEL_3(JMP, JGT, K):
	TBD;
LABEL_3(JMP, JGE, K):
	TBD;

LABEL_2(MISC, TAX):
	TBD;

LABEL_2(MISC, TXA):
	TBD;

LABEL_2(LD, MEM):
	TBD;
LABEL_2(LD, IMM):
	TBD;
LABEL_2(LDX, MEM):
	TBD;
LABEL_2(LDX, IMM):
	TBD;

LABEL_3(LD, B, ABS):
	debug("ldb (K=%u, len=%u)\n", insn->k, state->packet_len);
	d = state->packet_len - insn->k;
	if (d >= 1) {
		state->A = read_u8(state->packet, insn->k);
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;
LABEL_3(LD, H, ABS):
	debug("ldh (K=%u, len=%u)\n", insn->k, state->packet_len);
	d = state->packet_len - insn->k;
	if (d >= 2) {
		state->A = read_u16(state->packet, insn->k);
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;
LABEL_3(LD, W, ABS):
	debug("ld (K=%u, len=%u)\n", insn->k, state->packet_len);
	d = state->packet_len - insn->k;
	if (d >= 4) {
		state->A = read_u32(state->packet, insn->k);
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;
LABEL_3(LD, B, IND):
	debug("ldb [k+x] (K=%u, X=%u, len=%u)\n", insn->k, state->X, state->packet_len);
	d = state->packet_len - (insn->k + state->X);
	if (d >= 1) {
		state->A = read_u8(state->packet, (insn->k + state->X));
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;
LABEL_3(LD, H, IND):
	debug("ldb [k+x] (K=%u, X=%u, len=%u)\n", insn->k, state->X, state->packet_len);
	d = state->packet_len - (insn->k + state->X);
	if (d >= 2) {
		state->A = read_u16(state->packet, (insn->k + state->X));
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;
LABEL_3(LD, W, IND):
	debug("ldb [k+x] (K=%u, X=%u, len=%u)\n", insn->k, state->X, state->packet_len);
	d = state->packet_len - (insn->k + state->X);
	if (d >= 4) {
		state->A = read_u32(state->packet, (insn->k + state->X));
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;

LABEL_3(LD, W, LEN):
	TBD;

LABEL_3(LDX, W, LEN):
	TBD;

LABEL_3(LDX, MSH, B):
	debug("ldxb (K=%u, len=%u)\n", insn->k, state->packet_len);
	d = state->packet_len - insn->k;
	if (d >= 1) {
		state->X = read_u8(state->packet, insn->k);
		debug("X=%u\n", state->X);
		state->X = (state->X & 0xf) << 2;
		debug("X=%u\n", state->X);
	} else {
		debug("out of bounds access\n");
		state->ret_value = 0;
		return 0;
	}
	CONT;

LABEL_3(ALU, ADD, X):
	TBD;
LABEL_3(ALU, ADD, K):
	TBD;
LABEL_3(ALU, SUB, X):
	TBD;
LABEL_3(ALU, SUB, K):
	TBD;
LABEL_3(ALU, MUL, X):
	TBD;
LABEL_3(ALU, MUL, K):
	TBD;
LABEL_3(ALU, DIV, X):
	TBD;
LABEL_3(ALU, DIV, K):
	TBD;
LABEL_3(ALU, AND, X):
	TBD;
LABEL_3(ALU, AND, K):
	TBD;
LABEL_3(ALU, OR, X):
	TBD;
LABEL_3(ALU, OR, K):
	TBD;
LABEL_3(ALU, LSH, X):
	TBD;
LABEL_3(ALU, LSH, K):
	TBD;
LABEL_3(ALU, RSH, X):
	TBD;
LABEL_3(ALU, RSH, K):
	TBD;

default_label:
	debug("bad insn opcode %04x\n", insn->opcode);
	return -EINVAL;

	return *insn_idx;
}

SEC("syscall") int test(struct cbpf_test_input *ctx)
{
	struct cbpf_state state = {};
	__u32 insn_idx = 0;
	int ret = 0;
	int i;

	if (!ctx)
		return -EINVAL;
	if (ctx->prog_len > BPF_MAXINSNS)
		return -EINVAL;
	if (ctx->packet_len > sizeof(packet))
		return -EINVAL;

	state.packet = packet;
	state.packet_len = ctx->packet_len;

	bpf_for(i, zero, ctx->prog_len) {
		ret = cbpf_update_state(&state, ctx->prog_len, &insn_idx);
		if (ret <= 0)
			break;
	}

	ret_value = state.ret_value;
	return ret;
}

char _license[] SEC("license") = "GPL";
