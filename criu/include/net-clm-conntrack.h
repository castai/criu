#ifndef __CR_NET_CLM_CONNTRACK_H__
#define __CR_NET_CLM_CONNTRACK_H__

struct cr_img;
struct nlmsghdr;

/*
 * Dump one netfilter netlink message to the image. For conntrack entries
 * with NAT applied (IPS_SRC_NAT / IPS_DST_NAT in CTA_STATUS), synthesize
 * CTA_NAT_SRC / CTA_NAT_DST attributes so the NAT binding survives
 * dump -> restore. Other subsystems, non-NAT'd entries, and malformed
 * messages are written through unchanged.
 *
 * See net-clm-conntrack.c for the full rationale.
 */
extern int dump_nf_ct_msg(struct cr_img *img, struct nlmsghdr *hdr);

#endif /* __CR_NET_CLM_CONNTRACK_H__ */
