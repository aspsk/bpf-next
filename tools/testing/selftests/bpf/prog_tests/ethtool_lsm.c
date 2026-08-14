// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <linux/ethtool_netlink.h>
#include <linux/genetlink.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "netdevsim_helpers.h"
#include "network_helpers.h"
#include "netlink_helpers.h"
#include "test_progs.h"

#include "ethtool_lsm.skel.h"

#define NETNS "ethtool_lsm_ns"

#define TEST_DENY_ERRNO EDOTDOT

static int ethnl_request(int fd, __u16 family_id, __u8 cmd, __u16 hdr_attr,
			 __u16 extra_nest, __u32 ifindex, bool dump)
{
	static __u32 sequence = 10;
	struct genl_req req = {};
	__u32 seq = sequence++;
	struct rtattr *nest;
	int err;

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = family_id;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
	req.nlh.nlmsg_seq = seq;
	req.genl.cmd = cmd;
	req.genl.version = ETHTOOL_GENL_VERSION;

	nest = addattr_nest(&req.nlh, sizeof(req), hdr_attr | NLA_F_NESTED);
	if (ifindex && addattr32(&req.nlh, sizeof(req),
				 ETHTOOL_A_HEADER_DEV_INDEX, ifindex))
		return -EMSGSIZE;
	if (addattr32(&req.nlh, sizeof(req), ETHTOOL_A_HEADER_FLAGS,
		      ETHTOOL_FLAG_COMPACT_BITSETS))
		return -EMSGSIZE;
	addattr_nest_end(&req.nlh, nest);

	if (extra_nest) {
		nest = addattr_nest(&req.nlh, sizeof(req),
				    extra_nest | NLA_F_NESTED);
		addattr_nest_end(&req.nlh, nest);
	}

	err = genl_send(fd, &req.nlh);
	if (err)
		return err;

	return genl_recv(fd, seq, family_id, dump);
}

static int ethtool_ioctl(const char *ifname, void *data)
{
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	strscpy(ifr.ifr_name, ifname);
	ifr.ifr_data = data;
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err)
		err = -errno;
	close(fd);

	return err;
}

/*
 * For every command except LINKSTATE_GET and CHANNELS_SET the hook runs before
 * the driver capability check, so an allowed request still fails afterwards
 * with whatever errno the driver produces. Only require that it is not ours.
 */
static void check_doit(struct ethtool_lsm *skel, int fd, __u16 family_id,
		       __u32 ifindex, __u8 cmd, __u16 hdr_attr, __u16 extra_nest)
{
	int err;

	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = cmd;
	skel->bss->target_sub_cmd = 0;
	skel->bss->allow = true;

	err = ethnl_request(fd, family_id, cmd, hdr_attr, extra_nest, ifindex, false);
	if (!ASSERT_NEQ(err, -TEST_DENY_ERRNO, "allowed"))
		return;

	skel->bss->allow = false;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, extra_nest, ifindex, false);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "denied");
}

/*
 * A dump which does not name a device walks every netdev in the namespace and
 * runs the hook once per device; naming one makes dumpit resolve just that one.
 */
static void check_dump(struct ethtool_lsm *skel, int fd, __u16 family_id,
		       __u32 ifindex, __u8 cmd, __u16 hdr_attr, bool single_dev)
{
	__u32 req_ifindex = single_dev ? ifindex : 0;
	int err;

	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = cmd;
	skel->bss->target_sub_cmd = 0;
	skel->bss->allow = true;

	err = ethnl_request(fd, family_id, cmd, hdr_attr, 0, req_ifindex, true);
	if (!ASSERT_NEQ(err, -TEST_DENY_ERRNO, "allowed"))
		return;

	skel->bss->allow = false;
	err = ethnl_request(fd, family_id, cmd, hdr_attr, 0, req_ifindex, true);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "denied");
}

static void check_ioctl(struct ethtool_lsm *skel, const char *ifname,
			__u32 ifindex)
{
	struct ethtool_value value = { .cmd = ETHTOOL_GLINK };
	int err;

	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = ETHTOOL_GLINK;
	skel->bss->target_sub_cmd = 0;
	skel->bss->allow = true;

	/*
	 * As on the netlink side the hook runs before the driver is consulted
	 * (dev_ethtool_locked() calls it ahead of ->begin and the per command
	 * dispatch), so a device without the op still reaches the hook and only
	 * then fails with the driver's errno.
	 */
	err = ethtool_ioctl(ifname, &value);
	if (!ASSERT_NEQ(err, -TEST_DENY_ERRNO, "ioctl_allowed"))
		return;

	skel->bss->allow = false;
	err = ethtool_ioctl(ifname, &value);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "ioctl_denied");
}

/*
 * ETHTOOL_PERQUEUE is the only request where sub_cmd differs from cmd: the
 * operation which will actually run is nested in sub_command. A policy which
 * only matches ctx->cmd therefore has a bypass, and ctx->sub_cmd is what
 * closes it.
 */
static void check_ioctl_sub_cmd(struct ethtool_lsm *skel, const char *ifname,
				__u32 ifindex)
{
	struct ethtool_coalesce coal = { .cmd = ETHTOOL_SCOALESCE };
	union {
		struct ethtool_per_queue_op op;
		char buf[sizeof(struct ethtool_per_queue_op) +
			 sizeof(struct ethtool_coalesce)];
	} req = {};
	int err;

	req.op.cmd = ETHTOOL_PERQUEUE;
	req.op.sub_command = ETHTOOL_SCOALESCE;
	/* empty queue_mask: the hook runs before the per-queue dispatch */

	/* the hook sees cmd == ETHTOOL_PERQUEUE ... */
	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = ETHTOOL_PERQUEUE;
	skel->bss->target_sub_cmd = 0;
	skel->bss->allow = false;
	err = ethtool_ioctl(ifname, &req.op);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "cmd_is_perqueue");

	/* ... so a rule written against ETHTOOL_SCOALESCE alone misses it */
	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = ETHTOOL_SCOALESCE;
	skel->bss->target_sub_cmd = 0;
	skel->bss->allow = false;
	err = ethtool_ioctl(ifname, &req.op);
	ASSERT_NEQ(err, -TEST_DENY_ERRNO, "cmd_only_rule_is_bypassed");

	/* matching sub_cmd closes the bypass ... */
	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = 0;
	skel->bss->target_sub_cmd = ETHTOOL_SCOALESCE;
	skel->bss->allow = false;
	err = ethtool_ioctl(ifname, &req.op);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "perqueue_denied_by_sub_cmd");

	/* ... and still covers the plain request, where sub_cmd mirrors cmd */
	skel->bss->target_ifindex = ifindex;
	skel->bss->target_cmd = 0;
	skel->bss->target_sub_cmd = ETHTOOL_SCOALESCE;
	skel->bss->allow = false;
	err = ethtool_ioctl(ifname, &coal);
	ASSERT_EQ(err, -TEST_DENY_ERRNO, "scoalesce_denied_by_sub_cmd");
}

/*
 * Serial: the hooks are global, so an attached policy is visible to every task
 * on the machine, and netdevsim is created on a bus shared with other tests.
 */
void serial_test_ethtool_lsm(void)
{
	char nsim_name[IFNAMSIZ] = {};
	__u32 nsim_ifindex;
	struct ethtool_lsm *skel = NULL;
	struct netns_obj *netns = NULL;
	struct nstoken *nstoken = NULL;
	int nsim_id, family_id, fd = -1, err;

	nsim_id = netdevsim_create(nsim_name, sizeof(nsim_name));
	if (!ASSERT_GE(nsim_id, 0, "netdevsim_create"))
		return;

	/* reclaim the namespace if an earlier run was killed before cleanup */
	SYS_NOFAIL("ip netns del %s", NETNS);

	netns = netns_new(NETNS, false);
	if (!ASSERT_OK_PTR(netns, "netns_new"))
		goto out;

	SYS(out, "ip link set %s netns %s", nsim_name, NETNS);

	nstoken = open_netns(NETNS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto out;

	SYS(out, "ip link set %s up", nsim_name);

	nsim_ifindex = if_nametoindex(nsim_name);
	if (!ASSERT_NEQ(nsim_ifindex, 0, "nsim_ifindex"))
		goto out;

	skel = ethtool_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	/*
	 * The example policies deny for every task, so attaching them would
	 * enforce them machine-wide -- and cve_2024_46834_doit would collide
	 * head on with the channels_set case below. Loading them is the point,
	 * so leave them loaded but never attached.
	 */
	bpf_program__set_autoattach(skel->progs.cve_2021_46916, false);
	bpf_program__set_autoattach(skel->progs.cve_2025_21701, false);
	bpf_program__set_autoattach(skel->progs.cve_2022_50651, false);
	bpf_program__set_autoattach(skel->progs.cve_2024_46834_ioctl, false);
	bpf_program__set_autoattach(skel->progs.cve_2024_46834_doit, false);

	skel->bss->monitored_pid = getpid();

	err = ethtool_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	fd = genl_open(0);
	if (!ASSERT_OK_FD(fd, "genl_open"))
		goto out;

	family_id = genl_resolve_family(fd, ETHTOOL_GENL_NAME);
	if (!ASSERT_GT(family_id, 0, "resolve_ethtool_family"))
		goto out;

	if (test__start_subtest("linkstate_get_doit"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_LINKSTATE_GET, ETHTOOL_A_LINKSTATE_HEADER, 0);

	if (test__start_subtest("linkstate_get_dump"))
		check_dump(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_LINKSTATE_GET, ETHTOOL_A_LINKSTATE_HEADER, false);

	if (test__start_subtest("cable_test_act"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_CABLE_TEST_ACT, ETHTOOL_A_CABLE_TEST_HEADER, 0);

	if (test__start_subtest("cable_test_tdr_act"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
			   ETHTOOL_A_CABLE_TEST_TDR_HEADER, 0);

	/* FEATURES_SET bails out before the hook without a WANTED attribute */
	if (test__start_subtest("features_set"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_FEATURES_SET, ETHTOOL_A_FEATURES_HEADER,
			   ETHTOOL_A_FEATURES_WANTED);

	if (test__start_subtest("module_fw_flash_act"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
			   ETHTOOL_A_MODULE_FW_FLASH_HEADER, 0);

	if (test__start_subtest("tunnel_info_get_doit"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_TUNNEL_INFO_GET, ETHTOOL_A_TUNNEL_INFO_HEADER, 0);

	if (test__start_subtest("tunnel_info_get_dump"))
		check_dump(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_TUNNEL_INFO_GET, ETHTOOL_A_TUNNEL_INFO_HEADER,
			   false);

	if (test__start_subtest("tsinfo_get_dump"))
		check_dump(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_TSINFO_GET, ETHTOOL_A_TSINFO_HEADER, true);

	/* the only site which runs after ops->set_validate() */
	if (test__start_subtest("channels_set_doit"))
		check_doit(skel, fd, family_id, nsim_ifindex,
			   ETHTOOL_MSG_CHANNELS_SET, ETHTOOL_A_CHANNELS_HEADER, 0);

	if (test__start_subtest("ioctl"))
		check_ioctl(skel, nsim_name, nsim_ifindex);

	if (test__start_subtest("ioctl_sub_cmd"))
		check_ioctl_sub_cmd(skel, nsim_name, nsim_ifindex);

out:
	if (fd >= 0)
		close(fd);
	ethtool_lsm__destroy(skel);
	close_netns(nstoken);
	netns_free(netns);
	netdevsim_destroy(nsim_id);
}
