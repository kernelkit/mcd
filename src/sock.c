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
static int  reloading;			/* between sock_reload_begin/end */

/*
 * One packet socket per interface and family, shared and refcounted
 * by the entries on it.  The untagged entry is remembered, tagged
 * frames belong to the raw VLAN entry with that ID.
 */
struct sock {
    TAILQ_ENTRY(sock) link;
    int ifindex;
    int family;
    int sd;
    int id;				/* pev socket id */
    int refs;
    struct ifi *ifi;			/* untagged entry, if any */
};

static TAILQ_HEAD(, sock) socks = TAILQ_HEAD_INITIALIZER(socks);

/*
 * Kernel memberships held for static groups.  They are keyed by
 * interface and group, so a reload only touches groups that changed.
 */
struct member {
    TAILQ_ENTRY(member) link;
    int         ifindex;
    inet_addr_t group;
    int         stale;
};

static TAILQ_HEAD(, member) members = TAILQ_HEAD_INITIALIZER(members);

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

static void member_del(struct member *m)
{
    TAILQ_REMOVE(&members, m, link);
    free(m);
}

/*
 * Process exit, closing the join sockets drops every membership and
 * the kernel sends the leaves.
 */
void sock_exit(void)
{
    struct member *m, *tmp;

    TAILQ_FOREACH_SAFE(m, &members, link, tmp)
	member_del(m);

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
 * ancillary data.
 */
static void sock_read(int sd, void *arg)
{
    struct sock *sock = (struct sock *)arg;
    struct tpacket_auxdata *auxdata;
    struct sockaddr_ll sll = { 0 };
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    char cmbuf[0x100];
    struct iovec iov;
    struct ifi *ifi;
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

	warn("failed recvmsg() on ifindex %d", sock->ifindex);
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

    if (vid == 0 && sock->ifi)
	ifi = sock->ifi;
    else
	ifi = config_find_iface(sock->ifindex, vid, sock->family);
    if (!ifi)
	return;

    if (sock->family == AF_INET6)
	accept_mld(ifi, vid, recv_buf + ETH_HLEN, len - ETH_HLEN);
    else
	accept_igmp(ifi, vid, recv_buf + ETH_HLEN, len - ETH_HLEN);
}

static struct sock *sock_find(int ifindex, int family)
{
    struct sock *sock;

    TAILQ_FOREACH(sock, &socks, link) {
	if (sock->ifindex == ifindex && sock->family == family)
	    return sock;
    }

    return NULL;
}

static struct sock *sock_open(const struct ifi *ifi)
{
    struct sockaddr_ll sll = {
	.sll_family   = AF_PACKET,
	.sll_protocol = htons(ifi->ifi_family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP),
	.sll_ifindex  = ifi->ifi_index,
    };
    struct sock *sock;
    int ena = 1;

    sock = calloc(1, sizeof(*sock));
    if (!sock) {
	err("failed allocating packet socket for %s", ifi->ifi_name);
	exit(EX_OSERR);
    }

    sock->ifindex = ifi->ifi_index;
    sock->family  = ifi->ifi_family;
    sock->sd = socket(AF_PACKET, SOCK_RAW, sll.sll_protocol);
    if (sock->sd < 0) {
	err("failed creating raw packet socket");
	exit(EX_OSERR);
    }

    if (setsockopt(sock->sd, SOL_PACKET, PACKET_AUXDATA, &ena, sizeof(ena)) < 0) {
	err("failed enabling PACKET_AUXDATA on packet socket");
	exit(EX_OSERR);
    }

    if (set_filter(sock->sd, sock->family)) {
	err("failed setting socket filter");
	exit(EX_OSERR);
    }

    if (bind(sock->sd, (struct sockaddr *)&sll, sizeof(sll))) {
	err("failed binding socket to interface %s", ifi->ifi_name);
	exit(EX_OSERR);
    }

    sock->id = pev_sock_add(sock->sd, sock_read, sock);
    if (sock->id == -1) {
	err("failed registering packet handler");
	exit(EX_OSERR);
    }

    TAILQ_INSERT_TAIL(&socks, sock, link);

    return sock;
}

static void sock_close(struct sock *sock)
{
    pev_sock_del(sock->id);
    close(sock->sd);
    TAILQ_REMOVE(&socks, sock, link);
    free(sock);
}

void sock_iface_init(struct ifi *ifi)
{
    struct sock *sock;

    sock = sock_find(ifi->ifi_index, ifi->ifi_family);
    if (!sock)
	sock = sock_open(ifi);

    sock->refs++;
    if (!ifi->ifi_vlan)
	sock->ifi = ifi;
    ifi->ifi_sock = sock;
}

void sock_iface_exit(struct ifi *ifi)
{
    struct sock *sock = ifi->ifi_sock;

    if (!sock)
	return;

    if (sock->ifi == ifi)
	sock->ifi = NULL;
    ifi->ifi_sock = NULL;

    if (--sock->refs > 0 || reloading)
	return;

    sock_close(sock);
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

    if (sendto(ifi->ifi_sock->sd, send_buf, len, 0, (struct sockaddr *)&sll, sizeof(sll)) >= 0)
	return 0;

    if (errno == ENETDOWN) {
	iface_check_state();
	return 1;
    }

    return -1;
}

static int mcast_member(int ifindex, const inet_addr_t *group, int join)
{
    if (group->family == AF_INET6) {
	struct ipv6_mreq mreq = {
	    .ipv6mr_multiaddr = *inet_addr_get6(group),
	    .ipv6mr_interface = ifindex,
	};

	return setsockopt(join_sd6, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP,
			  &mreq, sizeof(mreq));
    } else {
	struct ip_mreqn mreq = {
	    .imr_multiaddr.s_addr = inet_addr_get4(group),
	    .imr_ifindex = ifindex,
	};

	return setsockopt(join_sd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
			  &mreq, sizeof(mreq));
    }
}

static struct member *member_find(int ifindex, const inet_addr_t *group)
{
    struct member *m;

    TAILQ_FOREACH(m, &members, link) {
	if (m->ifindex == ifindex && !inet_addr_cmp(&m->group, group))
	    return m;
    }

    return NULL;
}

int mcast_join(const struct ifi *ifi, const inet_addr_t *group)
{
    struct member *m;

    m = member_find(ifi->ifi_index, group);
    if (m) {
	m->stale = 0;
	return 0;
    }

    if (mcast_member(ifi->ifi_index, group, 1))
	return -1;

    m = calloc(1, sizeof(*m));
    if (!m) {
	err("failed allocating membership");
	exit(EX_OSERR);
    }

    m->ifindex = ifi->ifi_index;
    m->group   = *group;
    TAILQ_INSERT_TAIL(&members, m, link);

    return 0;
}

/*
 * Reload: memberships are marked, joins clear the mark, the rest are
 * left afterwards.  Packet sockets stay open until the new config is
 * in place, those nobody took up again are closed.
 */
void sock_reload_begin(void)
{
    struct member *m;

    TAILQ_FOREACH(m, &members, link)
	m->stale = 1;

    reloading = 1;
}

void sock_reload_end(void)
{
    struct member *m, *mtmp;
    struct sock *sock, *stmp;

    reloading = 0;
    TAILQ_FOREACH_SAFE(sock, &socks, link, stmp) {
	if (sock->refs == 0)
	    sock_close(sock);
    }

    TAILQ_FOREACH_SAFE(m, &members, link, mtmp) {
	if (!m->stale)
	    continue;

	mcast_member(m->ifindex, &m->group, 0);
	member_del(m);
    }
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
