/* SPDX-License-Identifier: ISC */

#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include "defs.h"
#include "inet.h"

uint8_t	   *recv_buf;			/* input packet buffer  */
uint8_t	   *send_buf;			/* output packet buffer */
static int  join_sd  = -1;		/* IPv4 static group memberships */
static int  join_sd6 = -1;		/* IPv6 static group memberships */

struct vlan {
    uint16_t tci;			/* PCP (3 bits), DEI (1 bit), VID (12 bits) */
    uint16_t tpid;			/* EtherType of encapsulated protocol      */
};

/*
 * The socket is bound to its family's EtherType, so the filter only
 * has to pick out IGMP, or MLD, which may sit behind a hop-by-hop
 * header where its Router Alert option lives.
 */
static int set_filter(int sd, int family)
{
    struct sock_filter igmp[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + offsetof(struct ip, ip_p)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_IGMP, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0),
    };
    struct sock_filter mld[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 3, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_HOPOPTS, 0, 3),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + sizeof(struct ip6_hdr)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0),
    };
    struct sock_fprog bpf = {
	.len    = family == AF_INET6 ? NELEMS(mld) : NELEMS(igmp),
	.filter = family == AF_INET6 ? mld : igmp,
    };

    return setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
}

void sock_init(void)
{
    recv_buf = calloc(1, RECV_BUF_SIZE);
    send_buf = calloc(1, RECV_BUF_SIZE);
    if (!recv_buf || !send_buf) {
	err("failed allocating Rx/Tx buffers");
	exit(EX_OSERR);
    }

    /* Never bound, so they never receive data, only hold memberships */
    join_sd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (join_sd < 0) {
	err("failed creating static group socket");
	exit(EX_OSERR);
    }
    join_sd6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (join_sd6 < 0)
	warn("failed creating IPv6 static group socket, no IPv6 static groups");
}

void sock_exit(void)
{
    if (join_sd >= 0)
	close(join_sd);
    if (join_sd6 >= 0)
	close(join_sd6);
    join_sd = join_sd6 = -1;

    free(recv_buf);
    free(send_buf);
}

/*
 * Frames arrive with the VLAN tag stripped, the ID is in the
 * ancillary data.  Dispatch on the family the socket is bound to.
 */
static void sock_read(int sd, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;
    struct tpacket_auxdata *auxdata;
    struct sockaddr_ll sll = { 0 };
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    char cmbuf[0x100];
    struct iovec iov;
    ssize_t len;
    int vid = 0;

    iov.iov_base = recv_buf;
    iov.iov_len = RECV_BUF_SIZE;
    msg.msg_name = &sll;
    msg.msg_namelen = sizeof(sll);
    msg.msg_control = cmbuf;
    msg.msg_controllen = sizeof(cmbuf);
    msg.msg_iov  = &iov;
    msg.msg_iovlen = 1;

    while ((len = recvmsg(sd, &msg, 0)) < 0) {
	if (errno == EINTR)
	    continue;

	warn("failed recvmsg() on %s", ifi->ifi_name);
	return;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
	    auxdata = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
	    vid = auxdata->tp_vlan_tci & 0x0fff;
	}
    }

    if ((size_t)len < sizeof(struct ether_header))
	return;

    if (ifi->ifi_family == AF_INET6)
	accept_mld(ifi, vid, recv_buf + ETH_HLEN, len - ETH_HLEN);
    else
	accept_igmp(ifi, vid, recv_buf + ETH_HLEN, len - ETH_HLEN);
}

void sock_iface_init(struct ifi *ifi)
{
    struct sockaddr_ll sll = {
	.sll_family   = AF_PACKET,
	.sll_protocol = htons(ifi->ifi_family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP),
	.sll_ifindex  = ifi->ifi_index,
    };
    int ena = 1;

    ifi->ifi_sock = socket(AF_PACKET, SOCK_RAW, sll.sll_protocol);
    if (ifi->ifi_sock < 0) {
	err("failed creating raw packet socket");
	exit(EX_OSERR);
    }

    if (setsockopt(ifi->ifi_sock, SOL_PACKET, PACKET_AUXDATA, &ena, sizeof(ena)) < 0) {
	err("failed enabling PACKET_AUXDATA on packet socket");
	exit(EX_OSERR);
    }

    if (set_filter(ifi->ifi_sock, ifi->ifi_family)) {
	err("failed setting socket filter");
	exit(EX_OSERR);
    }

    if (bind(ifi->ifi_sock, (struct sockaddr *)&sll, sizeof(sll))) {
	err("failed binding socket to interface %s", ifi->ifi_name);
	exit(EX_OSERR);
    }

    ifi->ifi_sockid = pev_sock_add(ifi->ifi_sock, sock_read, ifi);
    if (ifi->ifi_sockid == -1) {
	err("failed registering packet handler");
	exit(EX_OSERR);
    }
}

void sock_iface_exit(struct ifi *ifi)
{
    pev_sock_del(ifi->ifi_sockid);
    close(ifi->ifi_sock);
}

/*
 * Ethernet header, VLAN tagged in raw VLAN mode, to the given
 * multicast destination.  Returns the header length.
 */
size_t build_ether(uint8_t *buf, const struct ifi *ifi, const uint8_t *dmac, uint16_t proto)
{
    struct ether_header *eh = (struct ether_header *)buf;
    size_t len = sizeof(*eh);

    memcpy(eh->ether_dhost, dmac, sizeof(eh->ether_dhost));
    memcpy(eh->ether_shost, ifi->ifi_hwaddr, sizeof(eh->ether_shost));

    if (ifi->ifi_vlan) {
	struct vlan *v = (struct vlan *)(buf + len);
	uint16_t pcp = 6;

	eh->ether_type = htons(ETH_P_8021Q);
	v->tci  = htons((pcp << 13) | ifi->ifi_vlan);
	v->tpid = htons(proto);
	len += sizeof(*v);
    } else
	eh->ether_type = htons(proto);

    return len;
}

/*
 * Send len bytes from send_buf on the interface.  A link that went
 * down is handled here, anything else is the caller's to report.
 */
int sock_send(const struct ifi *ifi, size_t len)
{
    struct sockaddr_ll sll = {
	.sll_family   = AF_PACKET,
	.sll_protocol = htons(ETH_P_ALL),
	.sll_ifindex  = ifi->ifi_index,
    };

    if (sendto(ifi->ifi_sock, send_buf, len, 0, (struct sockaddr *)&sll, sizeof(sll)) >= 0)
	return 0;

    if (errno == ENETDOWN) {
	iface_check_state();
	return 1;
    }

    return -1;
}

static int mcast_member(const struct ifi *ifi, const inet_addr_t *group, int join)
{
    if (group->ss_family == AF_INET6) {
	struct ipv6_mreq mreq = {
	    .ipv6mr_multiaddr = *inet_addr_get6(group),
	    .ipv6mr_interface = ifi->ifi_index,
	};

	return setsockopt(join_sd6, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP,
			  &mreq, sizeof(mreq));
    } else {
	struct ip_mreqn mreq = {
	    .imr_multiaddr.s_addr = inet_addr_get4(group),
	    .imr_ifindex = ifi->ifi_index,
	};

	return setsockopt(join_sd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
			  &mreq, sizeof(mreq));
    }
}

int mcast_join(const struct ifi *ifi, const inet_addr_t *group)
{
    return mcast_member(ifi, group, 1);
}

int mcast_leave(const struct ifi *ifi, const inet_addr_t *group)
{
    return mcast_member(ifi, group, 0);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
