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

static bool is_nlctrl(const struct genl_family *family)
{
	static const char nlctrl_name[] = "nlctrl";
	char name[GENL_NAMSIZ];
	long len;

	len = BPF_CORE_READ_STR_INTO(&name, family, name);
	return len == sizeof(nlctrl_name) &&
	       bpf_strncmp(name, sizeof(nlctrl_name), nlctrl_name) == 0;
}

static int genl_family_rcv_msg_policy(const struct genl_family *family,
				      struct nlmsghdr *nlh,
				      const struct genl_split_ops *ops,
				      struct net *net, int ret)
{
	__u16 nlmsg_flags;
	__u32 cmd;
	__u32 pid;

	if (ret)
		return ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	if (!family || !nlh || !ops || !net || !is_nlctrl(family))
		return 0;

	nlmsg_flags = nlh->nlmsg_flags;
	cmd = ops->cmd;

	if (target_cmd && cmd != target_cmd)
		return 0;

	if (target_flags && nlmsg_flags != target_flags)
		return 0;

	if (target_netns_inum && net->ns.inum != target_netns_inum)
		return 0;

	return allow ? 0 : -EDOTDOT; /* unlikely to see this errno outside this test */
}

SEC("fmod_ret/genl_family_rcv_msg_doit")
int BPF_PROG(test_genl_family_rcv_msg_doit,
	     const struct genl_family *family, struct sk_buff *skb,
	     struct nlmsghdr *nlh, struct netlink_ext_ack *extack,
	     const struct genl_split_ops *ops, int hdrlen, struct net *net, int ret)
{
	return genl_family_rcv_msg_policy(family, nlh, ops, net, ret);
}

#if 0
SEC("fmod_ret/genl_family_rcv_msg_dumpit")
int BPF_PROG(test_genl_family_rcv_msg_dumpit,
	     const struct genl_family *family, struct sk_buff *skb,
	     struct nlmsghdr *nlh, struct netlink_ext_ack *extack,
	     const struct genl_split_ops *ops, int hdrlen, struct net *net, int ret)
{
	return genl_family_rcv_msg_policy(family, nlh, ops, net, ret);
}
#endif

char _license[] SEC("license") = "GPL";
