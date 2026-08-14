// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define GENL_NAMSIZ 16

__u32 monitored_pid;
__u32 target_cmd;
__u32 target_flags;
__u32 target_netns_inum;
bool allow;

static __always_inline bool is_nlctrl(const struct genl_family *family)
{
	char name[GENL_NAMSIZ];
	long len;

	len = BPF_CORE_READ_STR_INTO(&name, family, name);
	return len == sizeof("nlctrl") &&
	       bpf_strncmp(name, sizeof("nlctrl"), "nlctrl") == 0;
}

/*
 * Examples of coarse policies for vulnerabilities with no useful object to
 * authorize at a later, finer-grained hook:
 *
 * CVE-2022-50042 can be mitigated by denying family "nlctrl", command
 * CTRL_CMD_GETPOLICY with NLM_F_DUMP.  The leak is in
 * ctrl_dumppolicy_start() while constructing generic policy-dump state, so
 * distinguishing the target family does not make the vulnerable allocation
 * and error-unwind path safe.
 *
 * CVE-2023-53686 can be mitigated by denying family "handshake", command
 * HANDSHAKE_CMD_DONE.  The vulnerable error path dereferences the socket
 * after sockfd_lookup() failed; consequently there is no socket or handshake
 * request which a finer-grained hook could authorize.
 *
 * Only requests matching every target_* which is set are denied, so a test
 * can tell which value the hook was given without the program reporting it
 * back: the deny only lands when the context really carries those values.
 */
SEC("lsm/genl_family_rcv_msg")
int BPF_PROG(test_genl_family_rcv_msg, const struct genl_family *family,
	     const struct net *net, __u32 cmd, __u16 nlmsg_flags, int ret)
{
	__u32 pid;

	if (ret)
		return ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	if (!family || !net || !is_nlctrl(family))
		return 0;

	if (target_cmd && cmd != target_cmd)
		return 0;

	if (target_flags && nlmsg_flags != target_flags)
		return 0;

	if (target_netns_inum &&
	    BPF_CORE_READ(net, ns.inum) != target_netns_inum)
		return 0;

	return allow ? 0 : -EDOTDOT; /* unlikely to see this errno outside this test */
}

char _license[] SEC("license") = "GPL";
