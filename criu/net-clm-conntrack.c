
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>

#include "common/compiler.h"
#include "image.h"
#include "xmalloc.h"
#include "net-clm-conntrack.h"

#undef LOG_PREFIX
#define LOG_PREFIX "net-clm-conntrack: "

/*
 * The kernel's conntrack dump path (IPCTNL_MSG_CT_GET, NLM_F_DUMP) never emits
 * CTA_NAT_SRC / CTA_NAT_DST -- those attributes are input-only, consumed by
 * IPCTNL_MSG_CT_NEW to bind a NAT extension to the entry. And CTA_STATUS bits
 * IPS_{SRC,DST}_NAT{,_DONE} are in IPS_UNCHANGEABLE_MASK in the kernel, so
 * ctnetlink_change_status() silently strips them on replay.
 *
 * Result: round-tripping conntrack via dump->restore loses NAT bindings -- the
 * flow is re-tracked but reply packets are no longer reverse-translated,
 * breaking e.g. Istio's REDIRECT-based sidecar interception across migration.
 *
 * The NAT rewrite is recoverable from the two tuples the kernel does emit:
 *   reply.src <=> post-DNAT form of orig.dst   (when IPS_DST_NAT set)
 *   reply.dst <=> post-SNAT form of orig.src   (when IPS_SRC_NAT set)
 *
 * Synthesize CTA_NAT_SRC/CTA_NAT_DST from this delta at dump time so that the
 * on-disk message, when replayed through IPCTNL_MSG_CT_NEW, triggers the
 * kernel's ctnetlink_setup_nat() and re-binds NAT (which in turn sets the
 * status bits naturally).
 */

static int nat_nested_from_tuple_ip_port(uint8_t *out, int max, int nest_type,
					 uint8_t family, const void *ip, uint16_t port_be)
{
	struct nlattr *nat_attr, *proto_attr, *ip_attr;
	int iplen = (family == AF_INET) ? 4 : 16;
	int ip_min_type = (family == AF_INET) ? CTA_NAT_V4_MINIP : CTA_NAT_V6_MINIP;
	int ip_max_type = (family == AF_INET) ? CTA_NAT_V4_MAXIP : CTA_NAT_V6_MAXIP;
	uint8_t *p = out;
	int len;

	/* outer: CTA_NAT_{SRC,DST} (nested) */
	if ((int)NLA_HDRLEN > max)
		return -1;
	nat_attr = (struct nlattr *)p;
	nat_attr->nla_type = nest_type | NLA_F_NESTED;
	p += NLA_HDRLEN;

	/* CTA_NAT_V{4,6}_MINIP */
	len = NLA_HDRLEN + iplen;
	if ((p - out) + NLA_ALIGN(len) > max)
		return -1;
	ip_attr = (struct nlattr *)p;
	ip_attr->nla_type = ip_min_type;
	ip_attr->nla_len = len;
	memcpy(p + NLA_HDRLEN, ip, iplen);
	memset(p + NLA_HDRLEN + iplen, 0, NLA_ALIGN(len) - len);
	p += NLA_ALIGN(len);

	/* CTA_NAT_V{4,6}_MAXIP (same as MINIP -- single-value range) */
	ip_attr = (struct nlattr *)p;
	ip_attr->nla_type = ip_max_type;
	ip_attr->nla_len = len;
	memcpy(p + NLA_HDRLEN, ip, iplen);
	memset(p + NLA_HDRLEN + iplen, 0, NLA_ALIGN(len) - len);
	p += NLA_ALIGN(len);

	/* CTA_NAT_PROTO (nested) containing CTA_PROTONAT_PORT_{MIN,MAX} */
	if ((p - out) + NLA_HDRLEN > max)
		return -1;
	proto_attr = (struct nlattr *)p;
	proto_attr->nla_type = CTA_NAT_PROTO | NLA_F_NESTED;
	p += NLA_HDRLEN;

	len = NLA_HDRLEN + sizeof(uint16_t);
	if ((p - out) + 2 * NLA_ALIGN(len) > max)
		return -1;
	ip_attr = (struct nlattr *)p;
	ip_attr->nla_type = CTA_PROTONAT_PORT_MIN;
	ip_attr->nla_len = len;
	memcpy(p + NLA_HDRLEN, &port_be, sizeof(uint16_t));
	memset(p + NLA_HDRLEN + sizeof(uint16_t), 0, NLA_ALIGN(len) - len);
	p += NLA_ALIGN(len);

	ip_attr = (struct nlattr *)p;
	ip_attr->nla_type = CTA_PROTONAT_PORT_MAX;
	ip_attr->nla_len = len;
	memcpy(p + NLA_HDRLEN, &port_be, sizeof(uint16_t));
	memset(p + NLA_HDRLEN + sizeof(uint16_t), 0, NLA_ALIGN(len) - len);
	p += NLA_ALIGN(len);

	proto_attr->nla_len = (p - (uint8_t *)proto_attr);
	nat_attr->nla_len = (p - (uint8_t *)nat_attr);

	return p - out;
}

/*
 * Parse the reply tuple to pull out (family, src_ip, src_port, dst_ip, dst_port)
 * in the on-wire form. Returns 0 on success, -1 on malformed input.
 */
static int parse_reply_tuple(const struct nlattr *tuple_reply, uint8_t *family,
			     const void **src_ip, uint16_t *src_port,
			     const void **dst_ip, uint16_t *dst_port)
{
	struct nlattr *tb[CTA_TUPLE_MAX + 1];
	struct nlattr *tb_ip[CTA_IP_MAX + 1];
	struct nlattr *tb_proto[CTA_PROTO_MAX + 1];

	if (nla_parse_nested(tb, CTA_TUPLE_MAX, (struct nlattr *)tuple_reply, NULL) < 0)
		return -1;
	if (!tb[CTA_TUPLE_IP] || !tb[CTA_TUPLE_PROTO])
		return -1;
	if (nla_parse_nested(tb_ip, CTA_IP_MAX, tb[CTA_TUPLE_IP], NULL) < 0)
		return -1;
	if (nla_parse_nested(tb_proto, CTA_PROTO_MAX, tb[CTA_TUPLE_PROTO], NULL) < 0)
		return -1;

	if (tb_ip[CTA_IP_V4_SRC] && tb_ip[CTA_IP_V4_DST]) {
		*family = AF_INET;
		*src_ip = nla_data(tb_ip[CTA_IP_V4_SRC]);
		*dst_ip = nla_data(tb_ip[CTA_IP_V4_DST]);
	} else if (tb_ip[CTA_IP_V6_SRC] && tb_ip[CTA_IP_V6_DST]) {
		*family = AF_INET6;
		*src_ip = nla_data(tb_ip[CTA_IP_V6_SRC]);
		*dst_ip = nla_data(tb_ip[CTA_IP_V6_DST]);
	} else {
		return -1;
	}

	if (!tb_proto[CTA_PROTO_SRC_PORT] || !tb_proto[CTA_PROTO_DST_PORT])
		return -1;

	*src_port = *(uint16_t *)nla_data(tb_proto[CTA_PROTO_SRC_PORT]);
	*dst_port = *(uint16_t *)nla_data(tb_proto[CTA_PROTO_DST_PORT]);
	return 0;
}

/*
 * In-place rewrite: make `reply_tuple`'s leaf IP/port fields the inverse of
 * `orig_tuple` (swap src<->dst). Sizes are identical to the originals, so no
 * realloc is needed. Used together with synthesized CTA_NAT_*: the kernel's
 * nf_nat_setup_info() only flips IPS_*_NAT when its computed new_tuple
 * differs from invert(reply). Sending invert(orig) as the reply (i.e. the
 * pre-NAT form) guarantees that difference, so the rewrite materializes and
 * the bits are set as a side effect.
 */
static int invert_orig_into_reply(struct nlattr *orig_tuple, struct nlattr *reply_tuple)
{
	struct nlattr *o_tb[CTA_TUPLE_MAX + 1], *r_tb[CTA_TUPLE_MAX + 1];
	struct nlattr *o_ip[CTA_IP_MAX + 1], *r_ip[CTA_IP_MAX + 1];
	struct nlattr *o_pr[CTA_PROTO_MAX + 1], *r_pr[CTA_PROTO_MAX + 1];

	if (nla_parse_nested(o_tb, CTA_TUPLE_MAX, orig_tuple, NULL) < 0 ||
	    nla_parse_nested(r_tb, CTA_TUPLE_MAX, reply_tuple, NULL) < 0)
		return -1;
	if (!o_tb[CTA_TUPLE_IP] || !o_tb[CTA_TUPLE_PROTO] ||
	    !r_tb[CTA_TUPLE_IP] || !r_tb[CTA_TUPLE_PROTO])
		return -1;
	if (nla_parse_nested(o_ip, CTA_IP_MAX, o_tb[CTA_TUPLE_IP], NULL) < 0 ||
	    nla_parse_nested(r_ip, CTA_IP_MAX, r_tb[CTA_TUPLE_IP], NULL) < 0)
		return -1;
	if (nla_parse_nested(o_pr, CTA_PROTO_MAX, o_tb[CTA_TUPLE_PROTO], NULL) < 0 ||
	    nla_parse_nested(r_pr, CTA_PROTO_MAX, r_tb[CTA_TUPLE_PROTO], NULL) < 0)
		return -1;

	if (o_ip[CTA_IP_V4_SRC] && o_ip[CTA_IP_V4_DST] &&
	    r_ip[CTA_IP_V4_SRC] && r_ip[CTA_IP_V4_DST]) {
		memcpy(nla_data(r_ip[CTA_IP_V4_SRC]), nla_data(o_ip[CTA_IP_V4_DST]), 4);
		memcpy(nla_data(r_ip[CTA_IP_V4_DST]), nla_data(o_ip[CTA_IP_V4_SRC]), 4);
	} else if (o_ip[CTA_IP_V6_SRC] && o_ip[CTA_IP_V6_DST] &&
		   r_ip[CTA_IP_V6_SRC] && r_ip[CTA_IP_V6_DST]) {
		memcpy(nla_data(r_ip[CTA_IP_V6_SRC]), nla_data(o_ip[CTA_IP_V6_DST]), 16);
		memcpy(nla_data(r_ip[CTA_IP_V6_DST]), nla_data(o_ip[CTA_IP_V6_SRC]), 16);
	} else {
		return -1;
	}

	if (!o_pr[CTA_PROTO_SRC_PORT] || !o_pr[CTA_PROTO_DST_PORT] ||
	    !r_pr[CTA_PROTO_SRC_PORT] || !r_pr[CTA_PROTO_DST_PORT])
		return -1;
	memcpy(nla_data(r_pr[CTA_PROTO_SRC_PORT]),
	       nla_data(o_pr[CTA_PROTO_DST_PORT]), sizeof(uint16_t));
	memcpy(nla_data(r_pr[CTA_PROTO_DST_PORT]),
	       nla_data(o_pr[CTA_PROTO_SRC_PORT]), sizeof(uint16_t));
	return 0;
}

/*
 * Decode a single conntrack tuple (CTA_TUPLE_ORIG or CTA_TUPLE_REPLY) into
 * printable form. src_ip/dst_ip get an INET6_ADDRSTRLEN-sized buffer; ports
 * are returned in host order. Returns 0 on success, -1 if the tuple is
 * incomplete or malformed.
 *
 * Currently unused -- kept for future pr_debug() wiring.
 */
static __maybe_unused int format_ct_tuple(struct nlattr *tuple, uint8_t family,
					  char *src_ip, char *dst_ip, size_t ip_len,
					  uint8_t *l4proto, uint16_t *src_port, uint16_t *dst_port)
{
	struct nlattr *tb[CTA_TUPLE_MAX + 1];
	struct nlattr *tb_ip[CTA_IP_MAX + 1];
	struct nlattr *tb_proto[CTA_PROTO_MAX + 1];
	const void *src_raw, *dst_raw;
	int af = (family == AF_INET) ? AF_INET : AF_INET6;

	if (nla_parse_nested(tb, CTA_TUPLE_MAX, tuple, NULL) < 0)
		return -1;
	if (!tb[CTA_TUPLE_IP] || !tb[CTA_TUPLE_PROTO])
		return -1;
	if (nla_parse_nested(tb_ip, CTA_IP_MAX, tb[CTA_TUPLE_IP], NULL) < 0)
		return -1;
	if (nla_parse_nested(tb_proto, CTA_PROTO_MAX, tb[CTA_TUPLE_PROTO], NULL) < 0)
		return -1;

	if (family == AF_INET) {
		if (!tb_ip[CTA_IP_V4_SRC] || !tb_ip[CTA_IP_V4_DST])
			return -1;
		src_raw = nla_data(tb_ip[CTA_IP_V4_SRC]);
		dst_raw = nla_data(tb_ip[CTA_IP_V4_DST]);
	} else {
		if (!tb_ip[CTA_IP_V6_SRC] || !tb_ip[CTA_IP_V6_DST])
			return -1;
		src_raw = nla_data(tb_ip[CTA_IP_V6_SRC]);
		dst_raw = nla_data(tb_ip[CTA_IP_V6_DST]);
	}

	if (!inet_ntop(af, src_raw, src_ip, ip_len))
		return -1;
	if (!inet_ntop(af, dst_raw, dst_ip, ip_len))
		return -1;

	*l4proto = tb_proto[CTA_PROTO_NUM] ? nla_get_u8(tb_proto[CTA_PROTO_NUM]) : 0;
	*src_port = tb_proto[CTA_PROTO_SRC_PORT]
			    ? ntohs(*(uint16_t *)nla_data(tb_proto[CTA_PROTO_SRC_PORT])) : 0;
	*dst_port = tb_proto[CTA_PROTO_DST_PORT]
			    ? ntohs(*(uint16_t *)nla_data(tb_proto[CTA_PROTO_DST_PORT])) : 0;
	return 0;
}

int dump_nf_ct_msg(struct cr_img *img, struct nlmsghdr *hdr)
{
	struct nfgenmsg *nfm;
	struct nlattr *tb[CTA_MAX + 1];
	uint32_t status;
	uint8_t subsys;

	subsys = hdr->nlmsg_type >> 8;

	/*
	 * Only conntrack entries carry NAT; expectations go through
	 * CTNETLINK_EXP which has a separate attr space.
	 */
	if (subsys != NFNL_SUBSYS_CTNETLINK)
		goto write_as_is;

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg)))
		goto write_as_is;

	nfm = NLMSG_DATA(hdr);
	if (nfm->nfgen_family != AF_INET && nfm->nfgen_family != AF_INET6)
		goto write_as_is;

	if (nlmsg_parse(hdr, sizeof(struct nfgenmsg), tb, CTA_MAX, NULL) < 0)
		goto write_as_is;

	if (!tb[CTA_STATUS] || !tb[CTA_TUPLE_REPLY] || !tb[CTA_TUPLE_ORIG])
		goto write_as_is;

	status = ntohl(nla_get_u32(tb[CTA_STATUS]));
	if (!(status & (IPS_SRC_NAT | IPS_DST_NAT)))
		goto write_as_is;

	/*
	 * Synthesize CTA_NAT_SRC and/or CTA_NAT_DST into a copy of the
	 * netlink message. On replay, ctnetlink_setup_nat() will re-bind NAT
	 * from these attrs (and set the status bits as a side effect).
	 */
	{
		uint8_t family;
		const void *rsrc_ip, *rdst_ip;
		uint16_t rsrc_port, rdst_port;
		struct nlmsghdr *new_hdr;
		uint32_t old_len;
		uint8_t appended[256]; /* max 2 * CTA_NAT_* nestings, always fits */
		int appended_len = 0;
		int n;
		int ret;

		if (parse_reply_tuple(tb[CTA_TUPLE_REPLY], &family,
				      &rsrc_ip, &rsrc_port, &rdst_ip, &rdst_port) < 0)
			goto write_as_is;

		if (status & IPS_DST_NAT) {
			/* orig.dst was rewritten; reply.src reveals the rewrite target */
			n = nat_nested_from_tuple_ip_port(appended + appended_len,
							  sizeof(appended) - appended_len,
							  CTA_NAT_DST, family,
							  rsrc_ip, rsrc_port);
			if (n < 0)
				goto write_as_is;
			appended_len += n;
		}
		if (status & IPS_SRC_NAT) {
			/* orig.src was rewritten; reply.dst reveals the rewrite target */
			n = nat_nested_from_tuple_ip_port(appended + appended_len,
							  sizeof(appended) - appended_len,
							  CTA_NAT_SRC, family,
							  rdst_ip, rdst_port);
			if (n < 0)
				goto write_as_is;
			appended_len += n;
		}

		if (appended_len == 0)
			goto write_as_is;

		old_len = hdr->nlmsg_len;
		new_hdr = xmalloc(NLMSG_ALIGN(old_len) + appended_len);
		if (!new_hdr)
			return -1;

		memcpy(new_hdr, hdr, old_len);
		/* Pad out to align the appended attrs on a 4-byte boundary. */
		if (NLMSG_ALIGN(old_len) != old_len)
			memset((uint8_t *)new_hdr + old_len, 0,
			       NLMSG_ALIGN(old_len) - old_len);
		memcpy((uint8_t *)new_hdr + NLMSG_ALIGN(old_len), appended, appended_len);
		new_hdr->nlmsg_len = NLMSG_ALIGN(old_len) + appended_len;

		/*
		 * Replace the (post-NAT) reply tuple in the dumped message with
		 * invert(orig). On replay, that gives ctnetlink_setup_nat() a
		 * non-trivial range to apply, so the kernel re-derives the
		 * post-NAT reply tuple from our CTA_NAT_* and sets IPS_*_NAT.
		 * Without this rewrite, new_tuple == invert(reply) and the
		 * bit-flipping branch in nf_nat_setup_info() is skipped.
		 */
		{
			struct nlattr *new_tb[CTA_MAX + 1];

			if (nlmsg_parse(new_hdr, sizeof(struct nfgenmsg), new_tb, CTA_MAX, NULL) < 0 ||
			    !new_tb[CTA_TUPLE_ORIG] || !new_tb[CTA_TUPLE_REPLY] ||
			    invert_orig_into_reply(new_tb[CTA_TUPLE_ORIG], new_tb[CTA_TUPLE_REPLY]) < 0) {
				xfree(new_hdr);
				goto write_as_is;
			}
		}

		ret = write_img_buf(img, new_hdr, new_hdr->nlmsg_len);
		xfree(new_hdr);
		return ret;
	}

write_as_is:
	if (write_img_buf(img, hdr, hdr->nlmsg_len))
		return -1;

	return 0;
}
