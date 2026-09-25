#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>
#include <libnl3/netlink/netlink.h>

#include "types.h"
#include "log.h"
#include "util.h"
#include "namespaces.h"
#include "net.h"
#include "fdstore.h"
#include "files.h"
#include "image.h"
#include "bfd.h"
#include "libnetlink.h"
#include "cr_options.h"
#include "nested-ns.h"

#include "protobuf.h"
#include "images/netdev.pb-c.h"

#ifndef VETH_INFO_MAX
enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX (__VETH_INFO_MAX - 1)
};
#define VETH_INFO_PEER VETH_INFO_PEER
#endif

/*
 * The bridge of the inner runtime (e.g. the docker0 of a
 * docker-in-docker) lives in the network namespace of the migrated
 * container, which the runtime hands over to the network plugin of
 * the node instead of migrating it: the fresh one of the clone pod
 * does not have it. The veth pairs of the inner containers connect
 * them to it: the container ends live in their nested network
 * namespaces, which are re-created empty on restore (only the
 * loopback is brought up by the task entering them, the links and
 * the addresses are left to this one).
 *
 * This runs in the context of the restore service, after every task
 * of the tree is restored and before the network is unlocked: it
 * runs with the capabilities of the node, which cover both the
 * network namespace of the container and the nested ones (owned by
 * the descendants of the user namespace of the first one). It
 * re-creates the bridge in the network namespace of the container
 * from the images of the inner containers (the gateway of the
 * default route of the first one is the address of the bridge, the
 * prefix of the address of its veth gives the one of the network),
 * then the pairs themselves: the container ends are placed into the
 * nested network namespaces with their names, MACs, addresses and
 * routes from the images, the bridge ends are attached to the bridge.
 *
 * The network namespace of the container is not migrated on purpose
 * (it is the one of the network plugin), so the rules of the
 * iptables of the inner runtime (e.g. the masquerade of the outgoing
 * traffic of the containers) are lost with it: only the paths inside
 * the namespace of the container are re-created here.
 */

struct inner_veth {
	struct inner_veth *next;
	unsigned int ns_id;		/* the image id of the nested netns */
	int nsfd;			/* the fd of it, from the fdstore */
	char name[IFNAMSIZ];		/* the name of the container end */
	unsigned char mac[6];		/* its MAC address */
	unsigned int mtu;
	unsigned int ifindex;		/* the dump-time one, to match the images */
	__u32 addr;			/* its IPv4 address (network order) */
	unsigned int prefixlen;
	bool has_addr;
	__u32 gw;			/* the gateway of its default route */
};

struct inner_ns {
	struct inner_ns *next;
	unsigned int ns_id;
	int nsfd;
	struct inner_veth *veths;
};

/*
 * Walk the raw blob of an ip(8) dump (a sequence of netlink messages,
 * see run_ip_tool) with the given callback.
 */
/*
 * The image is the raw dump of the tools of the iproute2 suite (see
 * run_ip_tool): after the magic of the image it is the netlink
 * messages of the dump, back to back, walked with their own lengths.
 */
static int inner_dump_foreach(int type, unsigned int nsid,
			       int (*cb)(struct nlmsghdr *, void *), void *arg)
{
	struct cr_img *img;
	char buf[16384];
	ssize_t len;

	img = open_image(type, O_RSTR, nsid);
	if (!img && errno == ENOENT)
		return 0;
	if (!img)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return 0;
	}

	/* The lazy ones are opened here: their magic is not read yet. */
	if (img_raw_fd(img) < 0) {
		close_image(img);
		return -1;
	}
	{
		u32 magic;

		if (bread(&img->_x, &magic, sizeof(magic)) != sizeof(magic)) {
			close_image(img);
			return -1;
		}
	}

	while ((len = bread(&img->_x, buf, sizeof(buf))) > 0) {
		struct nlmsghdr *h;
		size_t rem = (size_t)len;

		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
			if (cb(h, arg))
				goto out;
		}
	}
out:
	close_image(img);
	return 0;
}

/*
 * The attributes are walked by hand: the parser of the netlink
 * library rejects the messages of the dumps of the tools of the
 * iproute2 suite (e.g. the unaligned one of the label of an
 * address) instead of skipping them.
 */
static int inner_attrs(struct nlmsghdr *h, size_t hdrlen, struct rtattr *tb[], int maxtype)
{
	struct rtattr *rta;
	size_t rem = h->nlmsg_len - NLMSG_LENGTH(hdrlen);

	memset(tb, 0, (maxtype + 1) * sizeof(*tb));
	for (rta = (struct rtattr *)((char *)NLMSG_DATA(h) + NLMSG_ALIGN(hdrlen)); RTA_OK(rta, rem);
	     rta = RTA_NEXT(rta, rem)) {
		if (rta->rta_type <= maxtype)
			tb[rta->rta_type] = rta;
	}

	return 0;
}

static int inner_ifaddr_cb(struct nlmsghdr *h, void *arg)
{
	struct inner_veth *veths = arg, *v;
	struct ifaddrmsg *ifa = NLMSG_DATA(h);
	struct rtattr *tb[IFA_MAX + 1];
	__u32 addr;

	if (h->nlmsg_type != RTM_NEWADDR || ifa->ifa_family != AF_INET)
		return 0;

	inner_attrs(h, sizeof(struct ifaddrmsg), tb, IFA_MAX);
	if (!tb[IFA_LOCAL] && !tb[IFA_ADDRESS])
		return 0;

	memcpy(&addr, RTA_DATA(tb[IFA_LOCAL] ? tb[IFA_LOCAL] : tb[IFA_ADDRESS]), 4);


	for (v = veths; v; v = v->next) {
		if (v->ifindex == ifa->ifa_index) {
			v->addr = addr;
			v->prefixlen = ifa->ifa_prefixlen;
			v->has_addr = true;
			break;
		}
	}

	return 0;
}

static int inner_route_cb(struct nlmsghdr *h, void *arg)
{
	struct inner_veth *veths = arg, *v;
	struct rtmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[RTA_MAX + 1];
	__u32 gw, oif = 0;

	if (h->nlmsg_type != RTM_NEWROUTE || r->rtm_family != AF_INET)
		return 0;
	if (r->rtm_dst_len != 0)
		return 0;		/* only the default route is of interest */

	inner_attrs(h, sizeof(struct rtmsg), tb, RTA_MAX);
	if (!tb[RTA_GATEWAY])
		return 0;

	memcpy(&gw, RTA_DATA(tb[RTA_GATEWAY]), 4);
	if (tb[RTA_OIF])
		memcpy(&oif, RTA_DATA(tb[RTA_OIF]), sizeof(oif));


	for (v = veths; v; v = v->next) {
		if (oif && v->ifindex == oif) {
			v->gw = gw;
			break;
		}
	}

	return 0;
}

static int collect_inner_ns(struct inner_ns **head, struct ns_id *ns)
{
	struct inner_ns *in, *t;
	struct cr_img *img;
	NetDeviceEntry *nde;
	int ret;

	in = xzalloc(sizeof(*in));
	if (!in)
		return -1;
	in->ns_id = ns->id;
	in->nsfd = fdstore_get(ns->net.nsfd_id);
	if (in->nsfd < 0) {
		pr_err("The fd of the nested netns %u is not in the fdstore\n", ns->id);
		xfree(in);
		return -1;
	}

	img = open_image(CR_FD_NETDEV, O_RSTR, ns->id);
	if (!img) {
		xfree(in);
		return -1;
	}

	while (1) {
		struct inner_veth *v;

		ret = pb_read_one_eof(img, &nde, PB_NETDEV);
		if (ret <= 0)
			break;

		if (nde->type != ND_TYPE__VETH || !strcmp(nde->name, "lo"))
			continue;

		v = xzalloc(sizeof(*v));
		if (!v) {
			close_image(img);
			xfree(in);
			return -1;
		}
		v->ns_id = ns->id;
		v->nsfd = in->nsfd;
		strncpy(v->name, nde->name, IFNAMSIZ - 1);
		if (nde->address.len > 0 && nde->address.len <= sizeof(v->mac))
			memcpy(v->mac, nde->address.data, nde->address.len);
		v->mtu = nde->mtu;
		v->ifindex = nde->ifindex;
		v->next = in->veths;
		in->veths = v;
	}

	close_image(img);

	if (!in->veths) {
		close(in->nsfd);
		xfree(in);
		return 0;
	}

	if (!*head) {
		*head = in;
	} else {
		for (t = *head; t->next; t = t->next)
			;
		t->next = in;
	}

	return 0;
}

static int link_index_by_name(int sk, const char *name)
{
	/* The index of the given link in the network namespace of the socket */
	struct {
		struct nlmsghdr h;
		struct rtgenmsg g;
	} req;
	struct nlmsghdr *h;
	struct rtattr *ifa[IFLA_MAX + 1];
	struct ifinfomsg *ifi;
	char buf[16384];
	ssize_t len;
	int idx = 0;

	/*
	 * The sequence of the dump differs from the one of the acks of
	 * the requests done via do_rtnl_req() on the same socket, so a
	 * stale one of them does not end this lookup before the dump.
	 */
	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.g));
	req.h.nlmsg_type = RTM_GETLINK;
	req.h.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.h.nlmsg_seq = CR_NLMSG_SEQ + 1;
	req.g.rtgen_family = AF_UNSPEC;

	if (send(sk, &req, req.h.nlmsg_len, 0) < 0) {
		pr_perror("Can't send the link dump request");
		return -1;
	}

	while (1) {
		len = recv(sk, buf, sizeof(buf), 0);
		if (len <= 0) {
			pr_perror("Can't recv the link dump");
			return -1;
		}
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_seq != CR_NLMSG_SEQ + 1)
				continue;
			if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
				return idx;
			ifi = NLMSG_DATA(h);
			inner_attrs(h, sizeof(struct ifinfomsg), ifa, IFLA_MAX);
			if (ifa[IFLA_IFNAME] && !strcmp(RTA_DATA(ifa[IFLA_IFNAME]), name))
				return ifi->ifi_index;
		}
	}
}

static int create_bridge(int sk, __u32 addr, unsigned int prefixlen)
{
	/* Create the docker0 bridge with the given address, or reuse it */
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
		char buf[256];
	} req;
	struct {
		struct nlmsghdr h;
		struct ifaddrmsg a;
		char buf[128];
	} areq;
	int idx;

	idx = link_index_by_name(sk, "docker0");
	if (idx > 0)
		return idx;		/* a retry of the same restore found it */

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_UNSPEC;
	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, "docker0", strlen("docker0") + 1);
	{
		struct rtattr *li, *info;

		li = NLMSG_TAIL(&req.h);
		addattr_l(&req.h, sizeof(req), IFLA_LINKINFO, NULL, 0);
		addattr_l(&req.h, sizeof(req), IFLA_INFO_KIND, "bridge", strlen("bridge"));
		info = NLMSG_TAIL(&req.h);
		addattr_l(&req.h, sizeof(req), IFLA_INFO_DATA, NULL, 0);
		info->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)info;
		li->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)li;
	}
	if (do_rtnl_req(sk, &req, req.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
		pr_err("Can't create the docker0 bridge of the inner runtime\n");
		return -1;
	}

	idx = link_index_by_name(sk, "docker0");
	if (idx <= 0) {
		pr_err("Can't find the docker0 bridge\n");
		return -1;
	}

	memset(&areq, 0, sizeof(areq));
	areq.h.nlmsg_len = NLMSG_LENGTH(sizeof(areq.a));
	areq.h.nlmsg_type = RTM_NEWADDR;
	areq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	areq.h.nlmsg_seq = CR_NLMSG_SEQ;
	areq.a.ifa_family = AF_INET;
	areq.a.ifa_prefixlen = prefixlen;
	areq.a.ifa_index = idx;
	addattr_l(&areq.h, sizeof(areq), IFA_LOCAL, &addr, 4);
	addattr_l(&areq.h, sizeof(areq), IFA_ADDRESS, &addr, 4);
	if (do_rtnl_req(sk, &areq, areq.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
		pr_err("Can't set the address of the docker0 bridge\n");
		return -1;
	}

	return idx;
}

static int set_link_up(int sk, int idx)
{
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
		char buf[64];
	} req;

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = idx;
	req.i.ifi_flags = IFF_UP;
	req.i.ifi_change = IFF_UP;
	if (do_rtnl_req(sk, &req, req.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
		pr_err("Can't bring the link %d up\n", idx);
		return -1;
	}

	return 0;
}

static int create_veth_pair(struct inner_veth *v, int sk, int master_idx)
{
	/*
	 * Create the pair with the container end moved into its network
	 * namespace straight away (the peer end of a veth accepts the
	 * IFLA_NET_NS_FD of its own): the bridge end stays here, named
	 * after the image id of the namespace, attached to the bridge.
	 */
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
		char buf[512];
	} req;
	struct rtattr *li, *info, *peer;
	char peer_name[IFNAMSIZ];
	struct ifinfomsg ifm;
	int pod_idx;

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_UNSPEC;

	snprintf(peer_name, sizeof(peer_name), "veth%d", v->ns_id);
	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, peer_name, strlen(peer_name) + 1);
	addattr_l(&req.h, sizeof(req), IFLA_MASTER, &master_idx, sizeof(master_idx));

	li = NLMSG_TAIL(&req.h);
	addattr_l(&req.h, sizeof(req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.h, sizeof(req), IFLA_INFO_KIND, "veth", strlen("veth"));
	info = NLMSG_TAIL(&req.h);
	addattr_l(&req.h, sizeof(req), IFLA_INFO_DATA, NULL, 0);
	peer = NLMSG_TAIL(&req.h);

	memset(&ifm, 0, sizeof(ifm));
	addattr_l(&req.h, sizeof(req), VETH_INFO_PEER, &ifm, sizeof(ifm));
	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, v->name, strlen(v->name) + 1);
	addattr_l(&req.h, sizeof(req), IFLA_ADDRESS, v->mac, sizeof(v->mac));
	if (v->mtu)
		addattr_l(&req.h, sizeof(req), IFLA_MTU, &v->mtu, sizeof(v->mtu));
	addattr_l(&req.h, sizeof(req), IFLA_NET_NS_FD, &v->nsfd, sizeof(v->nsfd));

	peer->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)peer;
	info->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)info;
	li->rta_len = (void *)NLMSG_TAIL(&req.h) - (void *)li;

	if (do_rtnl_req(sk, &req, req.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
		pr_err("Can't create the veth %s of the nested netns %u\n", v->name, v->ns_id);
		return -1;
	}

	pod_idx = link_index_by_name(sk, peer_name);
	if (pod_idx <= 0) {
		pr_err("Can't find the %s end of the pair\n", peer_name);
		return -1;
	}

	return pod_idx;
}

static int setup_container_end(struct inner_veth *v, int root_fd)
{
	/*
	 * Enter the network namespace of the container, find the index of
	 * its end of the pair, set the address and the default route of
	 * the images on it, and bring it up.
	 */
	struct {
		struct nlmsghdr h;
		struct ifaddrmsg a;
		char buf[128];
	} areq;
	struct {
		struct nlmsghdr h;
		struct rtmsg r;
		char buf[128];
	} rreq;
	int sk, idx, ret = -1;

	if (setns(v->nsfd, CLONE_NEWNET)) {
		pr_perror("Can't enter the netns %u", v->ns_id);
		return -1;
	}

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open a rtnl socket");
		goto out_ns;
	}

	idx = link_index_by_name(sk, v->name);
	if (idx <= 0) {
		pr_err("Can't find the %s link of the nested netns %u\n", v->name, v->ns_id);
		goto out_sk;
	}

	/* The link is brought up before the address and the route of it:
	 * the kernel rejects a gateway which is not reachable through an
	 * up one. */
	if (set_link_up(sk, idx))
		goto out_sk;

	if (v->has_addr) {
		memset(&areq, 0, sizeof(areq));
		areq.h.nlmsg_len = NLMSG_LENGTH(sizeof(areq.a));
		areq.h.nlmsg_type = RTM_NEWADDR;
		areq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
		areq.h.nlmsg_seq = CR_NLMSG_SEQ;
		areq.a.ifa_family = AF_INET;
		areq.a.ifa_prefixlen = v->prefixlen;
		areq.a.ifa_index = idx;
		addattr_l(&areq.h, sizeof(areq), IFA_LOCAL, &v->addr, 4);
		addattr_l(&areq.h, sizeof(areq), IFA_ADDRESS, &v->addr, 4);
		if (do_rtnl_req(sk, &areq, areq.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
			pr_err("Can't set the address of the %s link of the nested netns %u\n", v->name, v->ns_id);
			goto out_sk;
		}

		if (v->gw) {
			memset(&rreq, 0, sizeof(rreq));
			rreq.h.nlmsg_len = NLMSG_LENGTH(sizeof(rreq.r));
			rreq.h.nlmsg_type = RTM_NEWROUTE;
			rreq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
			rreq.h.nlmsg_seq = CR_NLMSG_SEQ;
			rreq.r.rtm_family = AF_INET;
			rreq.r.rtm_table = RT_TABLE_MAIN;
			rreq.r.rtm_protocol = RTPROT_STATIC;
			rreq.r.rtm_scope = RT_SCOPE_UNIVERSE;
			rreq.r.rtm_type = RTN_UNICAST;
			addattr_l(&rreq.h, sizeof(rreq), RTA_GATEWAY, &v->gw, 4);
			addattr_l(&rreq.h, sizeof(rreq), RTA_OIF, &idx, sizeof(idx));
			if (do_rtnl_req(sk, &rreq, rreq.h.nlmsg_len, NULL, NULL, NULL, NULL) < 0) {
				pr_err("Can't set the default route of the nested netns %u\n", v->ns_id);
				goto out_sk;
			}
		}
	}

	ret = 0;
out_sk:
	close(sk);
out_ns:
	if (setns(root_fd, CLONE_NEWNET)) {
		pr_perror("Can't return to the network namespace of the container");
		ret = -1;
	}
	return ret;
}

int nested_ns_restore_inner_network(void)
{
	struct ns_id *root_ns, *ns;
	struct inner_ns *inss = NULL, *in, *int2;
	struct inner_veth *v, *first = NULL;
	int root_fd = -1, sk = -1, bridge_idx = 0, pod_idx, ret = -1;

	if (!nested_ns_enabled()) {
		return 0;
	}

	root_ns = net_get_root_ns();
	if (!root_ns) {
		return 0;
	}

	for (ns = ns_ids; ns; ns = ns->next)
		if (ns->nd == &net_ns_desc && nested_ns_owned(ns))
			break;
	if (!ns) {
		return 0;
	}

	if (root_ns->ext_key) {
		root_fd = inherit_fd_lookup_id(root_ns->ext_key);
		if (root_fd < 0) {
			pr_err("Can't find the fd of the root netns %s\n", root_ns->ext_key);
			return -1;
		}
	} else if (root_ns->net.nsfd_id >= 0) {
		root_fd = fdstore_get(root_ns->net.nsfd_id);
		if (root_fd < 0) {
			pr_err("Can't get the fd of the root netns from the fdstore\n");
			return -1;
		}
	}

	/* The veths of the images, per their network namespace */
	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &net_ns_desc || !nested_ns_owned(ns))
			continue;
		if (collect_inner_ns(&inss, ns))
			goto out;
	}

	if (!inss) {
		ret = 0;
		goto out;
	}

	/* Match the addresses and the default routes of the images */
	for (in = inss; in; in = in->next) {
		if (inner_dump_foreach(CR_FD_IFADDR, in->ns_id, inner_ifaddr_cb, in->veths))
			goto out;
		if (inner_dump_foreach(CR_FD_ROUTE, in->ns_id, inner_route_cb, in->veths))
			goto out;
	}

	/*
	 * The bridge is created in the network namespace of the container
	 * with the address of the gateway of the first inner one having a
	 * default route: the default network of the inner runtime.
	 */
	for (in = inss; in && !first; in = in->next)
		for (v = in->veths; v; v = v->next)
			if (v->gw && v->has_addr) {
				first = v;
				break;
			}
	if (!first) {
		/*
		 * No inner container has a default route (e.g. they all
		 * run with --network none): nothing to connect them to.
		 */
		ret = 0;
		goto out;
	}

	if (setns(root_fd, CLONE_NEWNET)) {
		pr_perror("Can't enter the network namespace of the container");
		goto out;
	}

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open a rtnl socket");
		goto out;
	}

	bridge_idx = create_bridge(sk, first->gw, first->prefixlen);
	if (bridge_idx <= 0)
		goto out;

	if (set_link_up(sk, bridge_idx))
		goto out;

	for (in = inss; in; in = in->next) {
		for (v = in->veths; v; v = v->next) {
			if (!v->has_addr)
				continue;

			pod_idx = create_veth_pair(v, sk, bridge_idx);
			if (pod_idx <= 0)
				goto out;

			if (set_link_up(sk, pod_idx))
				goto out;

			if (setup_container_end(v, root_fd))
				goto out;
		}
	}

	ret = 0;
out:
	close_safe(&sk);
	if (root_fd >= 0)
		close(root_fd);
	for (in = inss; in; in = int2) {
		int2 = in->next;
		while (in->veths) {
			v = in->veths->next;
			xfree(in->veths);
			in->veths = v;
		}
		close(in->nsfd);
		xfree(in);
	}
	return ret;
}
