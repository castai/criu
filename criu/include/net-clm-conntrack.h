#ifndef __CRIU_NET_CLM_CONNTRACK_H__
#define __CRIU_NET_CLM_CONNTRACK_H__

#include <linux/netlink.h>

struct ns_id;

int is_nf_dsnat(struct nlmsghdr *hdr);

int dump_one_nf_dsnat(struct nlmsghdr *hdr, struct ns_id *ns, void *arg);

void log_ct_entry(struct nlmsghdr *nlh);

#endif /* __CRIU_NET_CLM_CONNTRACK_H__ */
