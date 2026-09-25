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
 * The bridge of an inner runtime (e.g. the docker0 of a
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
 * the descendants of the user namespace of the first one). It fills
 * the nested namespaces in from their images the way the restore of
 * a regular one does — the links, the addresses, the routes and the
 * sysctls of them — with the bridge ends of the pairs synthesized
 * in the network namespace of the container, as its own links are
 * not dumped (it is not migrated): one bridge per the gateway of
 * the default route of the containers of an inner network, the
 * group of the default network (the largest one) named docker0, so
 * the runtime of the inner containers keeps working after the
 * restore.
 *
 * The identifiers of the other network namespaces, the rules of the
 * policy routing and the iptables of the inner containers are not
 * restored: the first are needed for the pairs with both ends in
 * the dumped tree only, the other two are rare in a container (the
 * ones of the inner runtime live in the network namespace of the
 * container, which is not migrated, so the masquerade of the
 * outgoing traffic of the containers is lost with it).
 */

struct inner_addr {
	struct inner_addr *next;
	int family;			/* AF_INET or AF_INET6 */
	unsigned int prefixlen;
	unsigned char addr[16];		/* the address, network order */
};

struct inner_route {
	struct inner_route *next;
	int family;			/* AF_INET or AF_INET6 */
	unsigned int proto;
	unsigned int dst_len;
	unsigned char dst[16];		/* the destination, network order */
	bool has_gw;
	unsigned char gw[16];		/* the gateway, network order */
	unsigned int prio;		/* the metric of the route */
};

struct inner_veth {
	struct inner_veth *next;
	unsigned int ns_id;		/* the image id of the nested netns */
	int nsfd;			/* the fd of it, from the fdstore */
	char name[IFNAMSIZ];		/* the name of the container end */
	unsigned char mac[6];		/* its MAC address */
	unsigned int mtu;
	unsigned int ifindex;		/* the dump-time one, to match the images */
	struct inner_addr *addrs;	/* all the addresses of the images */
	struct inner_route *routes;	/* all the routes of them, the kernel
					 * made ones (the connected and the
					 * local ones) left out */
	__u32 gw4;			/* the gateway of the IPv4 default route,
					 * the key of the bridge group */
	bool has_gw4;
	unsigned int v4prefix;		/* the prefix of the first IPv4 address,
					 * the one of the bridge of the group */
};

struct inner_ns {
	struct inner_ns *next;
	unsigned int ns_id;
	int nsfd;
	struct inner_veth *veths;
};

struct inner_bridge {
	struct inner_bridge *next;
	char name[IFNAMSIZ];
	__u32 addr;			/* the gateway of the group */
	unsigned int prefixlen;
	bool has_addr;
	unsigned int nr;		/* the members of the group */
	int idx;
};

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

static int addrlen_by_family(int family)
{
	return family == AF_INET6 ? 16 : 4;
}

static int inner_ifaddr_cb(struct nlmsghdr *h, void *arg)
{
	struct inner_veth *veths = arg, *v;
	struct ifaddrmsg *ifa = NLMSG_DATA(h);
	struct rtattr *tb[IFA_MAX + 1];
	struct inner_addr *a;
	struct rtattr *src;
	int alen;

	if (h->nlmsg_type != RTM_NEWADDR)
		return 0;
	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return 0;

	inner_attrs(h, sizeof(struct ifaddrmsg), tb, IFA_MAX);
	src = tb[IFA_LOCAL] ? tb[IFA_LOCAL] : tb[IFA_ADDRESS];
	if (!src)
		return 0;

	alen = addrlen_by_family(ifa->ifa_family);
	if (RTA_PAYLOAD(src) < alen)
		return 0;

	/*
	 * The link-local address of an IPv6 interface is made by the
	 * kernel from the MAC of the link, which is restored with the
	 * link itself: the one of the image would clash with it.
	 */
	if (ifa->ifa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)RTA_DATA(src)))
		return 0;

	for (v = veths; v; v = v->next) {
		if (v->ifindex != ifa->ifa_index)
			continue;

		a = xzalloc(sizeof(*a));
		if (!a)
			return -1;
		a->family = ifa->ifa_family;
		a->prefixlen = ifa->ifa_prefixlen;
		memcpy(a->addr, RTA_DATA(src), alen);
		a->next = v->addrs;
		v->addrs = a;

		if (ifa->ifa_family == AF_INET && !v->v4prefix)
			v->v4prefix = ifa->ifa_prefixlen;

		break;
	}

	return 0;
}

static int inner_route_cb(struct nlmsghdr *h, void *arg)
{
	struct inner_veth *veths = arg, *v;
	struct rtmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[RTA_MAX + 1];
	struct inner_route *rt;
	__u32 oif = 0;
	int alen;

	if (h->nlmsg_type != RTM_NEWROUTE)
		return 0;
	if (r->rtm_family != AF_INET && r->rtm_family != AF_INET6)
		return 0;

	/*
	 * The routes made by the kernel itself (the connected and the
	 * local ones) are re-created with the addresses of the images:
	 * only the ones set up by the user space are restored.
	 */
	if (r->rtm_protocol == RTPROT_KERNEL)
		return 0;
	if (r->rtm_type != RTN_UNICAST)
		return 0;
	if (r->rtm_table != RT_TABLE_MAIN)
		return 0;
	if (r->rtm_dst_len > 8 * sizeof(((struct inner_route *)0)->dst))
		return 0;

	inner_attrs(h, sizeof(struct rtmsg), tb, RTA_MAX);
	if (tb[RTA_OIF])
		memcpy(&oif, RTA_DATA(tb[RTA_OIF]), sizeof(oif));
	if (!oif)
		return 0;

	for (v = veths; v; v = v->next) {
		if (v->ifindex != oif)
			continue;

		alen = addrlen_by_family(r->rtm_family);

		rt = xzalloc(sizeof(*rt));
		if (!rt)
			return -1;
		rt->family = r->rtm_family;
		rt->proto = r->rtm_protocol;
		rt->dst_len = r->rtm_dst_len;
		if (r->rtm_dst_len) {
			if (!tb[RTA_DST] || RTA_PAYLOAD(tb[RTA_DST]) < alen) {
				xfree(rt);
				return 0;
			}
			memcpy(rt->dst, RTA_DATA(tb[RTA_DST]), alen);
		}
		if (tb[RTA_GATEWAY]) {
			if (RTA_PAYLOAD(tb[RTA_GATEWAY]) < alen) {
				xfree(rt);
				return 0;
			}
			memcpy(rt->gw, RTA_DATA(tb[RTA_GATEWAY]), alen);
			rt->has_gw = true;
		}
		if (tb[RTA_PRIORITY])
			memcpy(&rt->prio, RTA_DATA(tb[RTA_PRIORITY]), sizeof(rt->prio));
		rt->next = v->routes;
		v->routes = rt;

		/* The IPv4 default route carries the gateway of the group. */
		if (r->rtm_family == AF_INET && r->rtm_dst_len == 0 && rt->has_gw) {
			memcpy(&v->gw4, rt->gw, 4);
			v->has_gw4 = true;
		}

		break;
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

		if (!strcmp(nde->name, "lo"))
			continue;

		if (nde->type != ND_TYPE__VETH) {
			/*
			 * A link with the peer or the parent in the
			 * network namespace of the container, which is
			 * not migrated: nothing to attach it to.
			 */
			pr_warn("The %s link of the nested netns %u (type %d) is not restored\n",
				nde->name, ns->id, nde->type);
			continue;
		}

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

/*
 * The error callback of the requests which are fine with the thing
 * they ask for being there already (a retry of a restore of the
 * same tree into the same namespaces).
 */
struct rtnl_tolerate {
	int err;		/* the positive errno to ignore */
};

static int tolerant_err_cb(int err, struct ns_id *ns, void *arg)
{
	if (err == -((struct rtnl_tolerate *)arg)->err)
		return 0;
	errno = -err;
	pr_perror("Netlink error");
	return err;
}

static int do_rtnl_req_tolerant(int sk, void *req, int len, int tolerated)
{
	struct rtnl_tolerate t = { .err = tolerated };

	return do_rtnl_req(sk, req, len, NULL, tolerant_err_cb, NULL, &t);
}

static int create_bridge(int sk, const char *name, __u32 addr, unsigned int prefixlen, bool has_addr)
{
	/* Create the bridge with the given address, or reuse it */
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

	idx = link_index_by_name(sk, name);
	if (idx > 0)
		return idx;		/* a retry of the same restore found it */

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_UNSPEC;
	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1);
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
		pr_err("Can't create the %s bridge of the inner runtime\n", name);
		return -1;
	}

	idx = link_index_by_name(sk, name);
	if (idx <= 0) {
		pr_err("Can't find the %s bridge\n", name);
		return -1;
	}

	if (has_addr) {
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
		if (do_rtnl_req_tolerant(sk, &areq, areq.h.nlmsg_len, EEXIST) < 0) {
			pr_err("Can't set the address of the %s bridge\n", name);
			return -1;
		}
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
	if (do_rtnl_req_tolerant(sk, &req, req.h.nlmsg_len, 0) < 0) {
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

	if (do_rtnl_req_tolerant(sk, &req, req.h.nlmsg_len, EEXIST) < 0) {
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

static int add_one_addr(int sk, int idx, struct inner_addr *a)
{
	struct {
		struct nlmsghdr h;
		struct ifaddrmsg i;
		char buf[128];
	} req;
	int alen = addrlen_by_family(a->family);

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWADDR;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifa_family = a->family;
	req.i.ifa_prefixlen = a->prefixlen;
	req.i.ifa_index = idx;
	addattr_l(&req.h, sizeof(req), IFA_LOCAL, a->addr, alen);
	addattr_l(&req.h, sizeof(req), IFA_ADDRESS, a->addr, alen);

	return do_rtnl_req_tolerant(sk, &req, req.h.nlmsg_len, EEXIST);
}

static int add_one_route(int sk, int idx, struct inner_route *r)
{
	struct {
		struct nlmsghdr h;
		struct rtmsg i;
		char buf[160];
	} req;
	int alen = addrlen_by_family(r->family);

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.h.nlmsg_type = RTM_NEWROUTE;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.rtm_family = r->family;
	req.i.rtm_table = RT_TABLE_MAIN;
	req.i.rtm_protocol = r->proto;
	req.i.rtm_scope = RT_SCOPE_UNIVERSE;
	req.i.rtm_type = RTN_UNICAST;
	req.i.rtm_dst_len = r->dst_len;
	if (r->dst_len)
		addattr_l(&req.h, sizeof(req), RTA_DST, r->dst, alen);
	if (r->has_gw)
		addattr_l(&req.h, sizeof(req), RTA_GATEWAY, r->gw, alen);
	addattr_l(&req.h, sizeof(req), RTA_OIF, &idx, sizeof(idx));
	if (r->prio)
		addattr_l(&req.h, sizeof(req), RTA_PRIORITY, &r->prio, sizeof(r->prio));

	return do_rtnl_req_tolerant(sk, &req, req.h.nlmsg_len, EEXIST);
}

static int setup_container_end(struct inner_veth *v, int root_fd)
{
	/*
	 * Enter the network namespace of the container and fill its end
	 * of the pair in from the images: the link is brought up first,
	 * as the kernel rejects a gateway which is not reachable through
	 * an up one, then the addresses and the routes of it are set.
	 */
	struct inner_addr *a;
	struct inner_route *r;
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

	if (set_link_up(sk, idx))
		goto out_sk;

	for (a = v->addrs; a; a = a->next) {
		if (add_one_addr(sk, idx, a) < 0) {
			pr_err("Can't set the address of the %s link of the nested netns %u\n",
			       v->name, v->ns_id);
			goto out_sk;
		}
	}

	for (r = v->routes; r; r = r->next) {
		if (add_one_route(sk, idx, r) < 0) {
			pr_err("Can't set the route of the nested netns %u\n", v->ns_id);
			goto out_sk;
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

/*
 * The sysctls of the network namespace (the conf of the interfaces
 * and the ones of the protocols), the way the restore of a regular
 * one applies them: a failure of one is not fatal for the restore,
 * the namespace works with the defaults of the kernel.
 */
static int setup_container_conf(struct inner_ns *in, int root_fd)
{
	struct ns_id *ns;
	int ret;

	ns = lookup_ns_by_id(in->ns_id, &net_ns_desc);
	if (!ns)
		return 0;

	if (setns(in->nsfd, CLONE_NEWNET)) {
		pr_perror("Can't enter the netns %u", in->ns_id);
		return -1;
	}

	ret = nested_ns_restore_conf(ns);
	if (ret)
		pr_warn("Can't restore the sysctls of the nested netns %u\n", in->ns_id);

	if (setns(root_fd, CLONE_NEWNET)) {
		pr_perror("Can't return to the network namespace of the container");
		return -1;
	}

	return 0;
}

/*
 * One bridge per the gateway of the default route of the containers
 * of an inner network: the group of the default one (the largest,
 * named docker0) and the ones of the user defined networks of the
 * inner runtime, named after their order. The ones without a gateway
 * of their own join the default group: nothing better is known about
 * them from the images.
 */
static struct inner_bridge *build_bridge_groups(struct inner_ns *inss)
{
	struct inner_bridge *bridges = NULL, *b, *def = NULL;
	struct inner_ns *in;
	struct inner_veth *v;
	int i;

	for (in = inss; in; in = in->next) {
		for (v = in->veths; v; v = v->next) {
			if (!v->has_gw4)
				continue;

			for (b = bridges; b; b = b->next)
				if (b->has_addr && b->addr == v->gw4) {
					b->nr++;
					break;
				}
			if (b)
				continue;

			b = xzalloc(sizeof(*b));
			if (!b)
				return NULL;
			b->has_addr = true;
			b->addr = v->gw4;
			b->prefixlen = v->v4prefix ? v->v4prefix : 16;
			b->nr = 1;
			b->next = bridges;
			bridges = b;
		}
	}

	if (!bridges) {
		/* No inner container has a gateway (a default route):
		 * one bridge without an address connects them all. */
		b = xzalloc(sizeof(*b));
		if (!b)
			return NULL;
		strncpy(b->name, "docker0", sizeof(b->name) - 1);
		return b;
	}

	/* The largest group is the default network of the inner runtime,
	 * its bridge takes the name the runtime expects of it. */
	for (b = bridges; b; b = b->next)
		if (!def || b->nr > def->nr)
			def = b;
	strncpy(def->name, "docker0", sizeof(def->name) - 1);

	for (b = bridges, i = 1; b; b = b->next)
		if (b != def)
			snprintf(b->name, sizeof(b->name), "br-criu%d", i++);

	return bridges;
}

int nested_ns_restore_inner_network(void)
{
	struct ns_id *root_ns, *ns;
	struct inner_ns *inss = NULL, *in, *int2;
	struct inner_veth *v;
	struct inner_bridge *bridges = NULL, *b, *b2;
	int root_fd = -1, sk = -1, pod_idx, ret = -1;

	if (!nested_ns_enabled())
		return 0;

	root_ns = net_get_root_ns();
	if (!root_ns)
		return 0;

	for (ns = ns_ids; ns; ns = ns->next)
		if (ns->nd == &net_ns_desc && nested_ns_owned(ns))
			break;
	if (!ns)
		return 0;

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

	/* Match the addresses and the routes of the images */
	for (in = inss; in; in = in->next) {
		if (inner_dump_foreach(CR_FD_IFADDR, in->ns_id, inner_ifaddr_cb, in->veths))
			goto out;
		if (inner_dump_foreach(CR_FD_ROUTE, in->ns_id, inner_route_cb, in->veths))
			goto out;
	}

	bridges = build_bridge_groups(inss);
	if (!bridges)
		goto out;

	if (setns(root_fd, CLONE_NEWNET)) {
		pr_perror("Can't enter the network namespace of the container");
		goto out;
	}

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open a rtnl socket");
		goto out;
	}

	/* The bridges of the inner networks in the namespace of the container */
	for (b = bridges; b; b = b->next) {
		b->idx = create_bridge(sk, b->name, b->addr, b->prefixlen, b->has_addr);
		if (b->idx <= 0)
			goto out;
		if (set_link_up(sk, b->idx))
			goto out;
	}

	for (in = inss; in; in = in->next) {
		if (setup_container_conf(in, root_fd))
			goto out;

		for (v = in->veths; v; v = v->next) {
			/* The bridge of the group of the veth: the one of
			 * its gateway, or the default one without it. */
			for (b = bridges; b; b = b->next)
				if (v->has_gw4 && b->has_addr && b->addr == v->gw4)
					break;
			if (!b)
				b = bridges;

			pod_idx = create_veth_pair(v, sk, b->idx);
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
	for (b = bridges; b; b = b2) {
		b2 = b->next;
		xfree(b);
	}
	for (in = inss; in; in = int2) {
		int2 = in->next;
		while (in->veths) {
			v = in->veths->next;
			while (in->veths->addrs) {
				struct inner_addr *a = in->veths->addrs->next;
				xfree(in->veths->addrs);
				in->veths->addrs = a;
			}
			while (in->veths->routes) {
				struct inner_route *r = in->veths->routes->next;
				xfree(in->veths->routes);
				in->veths->routes = r;
			}
			xfree(in->veths);
			in->veths = v;
		}
		close(in->nsfd);
		xfree(in);
	}
	return ret;
}
