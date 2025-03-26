#ifndef CBPF_COMMON_H
#define CBPF_COMMON_H

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

struct cbpf_test_input {
	__u32 prog_len;		/* prog len in instructions */
	__u32 packet_len;	/* packet len in bytes */
};


struct cbpf_insn {
	__u16 opcode;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

#endif
