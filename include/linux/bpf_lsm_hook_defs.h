// SPDX-License-Identifier: GPL-2.0

/*
 * This is a set of BPF LSM hooks, which are _not_ fully implemented
 * as LSM hooks. Thus, they only can be used by BPF LSM programs.
 */

#ifdef CONFIG_NET

LSM_HOOK(int, 0, genl_family_rcv_msg, const struct genl_family *family,
	 const struct net *net, u32 cmd, u16 nlmsg_flags)

LSM_HOOK(int, 0, ethtool_ioctl, struct bpf_ethtool_ctx *ctx)
LSM_HOOK(int, 0, ethtool_netlink_doit, struct bpf_ethtool_ctx *ctx)
LSM_HOOK(int, 0, ethtool_netlink_dump, struct bpf_ethtool_ctx *ctx)

#endif /* CONFIG_NET */
