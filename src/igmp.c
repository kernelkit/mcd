/* SPDX-License-Identifier: ISC */

#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include "defs.h"
#include "igmp.h"
#include "inet.h"

#define PIM_QUERY           0
#define PIM_REGISTER        1
#define PIM_REGISTER_STOP   2
#define PIM_JOIN_PRUNE      3
#define PIM_RP_REACHABLE    4
#define PIM_ASSERT          5
#define PIM_GRAFT           6
#define PIM_GRAFT_ACK       7

struct vlan {
	uint16_t tci;    /* Tag Control Information: PCP (3 bits), DEI (1 bit), VID (12 bits) */
	uint16_t tpid;   /* Tag Protocol ID (EtherType of encapsulated protocol) */
};

/*
 * Exported variables.
 */
uint8_t		*recv_buf; 		     /* input packet buffer         */
uint8_t		*send_buf; 		     /* output packet buffer        */
int             router_alert;		     /* IP option Router Alert      */
uint32_t        router_timeout;		     /* Other querier present intv. */
uint32_t	igmp_query_interval;	     /* Default: 125 sec            */
uint32_t	igmp_response_interval;	     /* Default: 10 sec             */
uint32_t	igmp_last_member_interval;   /* Default: 1                  */
uint32_t	igmp_robustness;	     /* Default: 2                  */
uint32_t	allhosts_group;		     /* All hosts addr in net order */
uint32_t	allrtrs_group;		     /* All-Routers "  in net order */
uint32_t	allreports_group;	     /* IGMPv3 member reports       */

/*
 * Private variables.
 */
static int	igmp_sockid;

/*
 * Local function definitions.
 */
static void	igmp_read(int sd, void *arg);
static size_t	build_ipv4(uint8_t *buf, uint32_t src, uint32_t dst, short unsigned int datalen);


static int set_filter(int sd)
{
	struct sock_filter code[] = {
		/* Load the IP protocol field from the IP header */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + offsetof(struct iphdr, protocol)),
		/* Check if it's IGMP (protocol number 2) */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_IGMP, 0, 1),
		/* Return -1 (all bytes) if the condition is true */
		BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
		/* Otherwise, ignore the packet */
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct sock_fprog bpf = {
		.len = sizeof(code) / sizeof(code[0]),
		.filter = code,
	};

	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		return -1;

	return 0;
}

/*
 * Open and initialize the igmp socket, and fill in the non-changing
 * IP header fields in the output packet buffer.
 */
void igmp_init(void)
{
    const int BUFSZ = 256 * 1024;
    const int MINSZ =  48 * 1024;

    recv_buf = calloc(1, RECV_BUF_SIZE);
    send_buf = calloc(1, RECV_BUF_SIZE);

    if (!recv_buf || !send_buf) {
	logit(LOG_ERR, errno, "Failed allocating Rx/Tx buffers");
	exit(1);
    }

    allhosts_group   = htonl(INADDR_ALLHOSTS_GROUP);
    allrtrs_group    = htonl(INADDR_ALLRTRS_GROUP);
    allreports_group = htonl(INADDR_ALLRPTS_GROUP);

    igmp_query_interval       = IGMP_QUERY_INTERVAL_DEFAULT;
    igmp_response_interval    = IGMP_QUERY_RESPONSE_INTERVAL;
    igmp_last_member_interval = IGMP_LAST_MEMBER_INTERVAL_DEFAULT;
    igmp_robustness           = IGMP_ROBUSTNESS_DEFAULT;
    router_timeout            = IGMP_OTHER_QUERIER_PRESENT_INTERVAL;
    router_alert              = 1;
}

void igmp_exit(void)
{
    free(recv_buf);
    free(send_buf);
}

void igmp_iface_init(struct ifi *ifi)
{
    struct sockaddr_ll sll = {
	.sll_family   = AF_PACKET,
	.sll_protocol = htons(ETH_P_ALL),
	.sll_ifindex  = ifi->ifi_index,
    };
    int ena = 1;

    ifi->ifi_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ifi->ifi_sock < 0)
	logit(LOG_ERR, errno, "Failed creating IGMP raw packet socket");

    if (setsockopt(ifi->ifi_sock, SOL_PACKET, PACKET_AUXDATA, &ena, sizeof(ena)) < 0)
	logit(LOG_ERR, errno, "Failed enabling PACKET_AUXDATA on IGMP socket");

    if (set_filter(ifi->ifi_sock))
	logit(LOG_ERR, errno, "Failed setting socket filter");

    if (bind(ifi->ifi_sock, (struct sockaddr *)&sll, sizeof(sll)))
	logit(LOG_ERR, errno, "Failed binding socket to interface %s", ifi->ifi_name);

    ifi->ifi_sockid = pev_sock_add(ifi->ifi_sock, igmp_read, ifi);
    if (ifi->ifi_sockid == -1)
	logit(LOG_ERR, errno, "Failed registering IGMP handler");
}

void igmp_iface_exit(struct ifi *ifi)
{
    pev_sock_del(ifi->ifi_sockid);
    close(ifi->ifi_sock);
}

char *igmp_packet_kind(uint32_t type, uint32_t code)
{
    static char unknown[20];

    switch (type) {
	case IGMP_MEMBERSHIP_QUERY:		return "membership query  ";
	case IGMP_V1_MEMBERSHIP_REPORT:		return "v1 member report  ";
	case IGMP_V2_MEMBERSHIP_REPORT:		return "v2 member report  ";
	case IGMP_V3_MEMBERSHIP_REPORT:		return "v3 member report  ";
	case IGMP_V2_LEAVE_GROUP:		return "leave message     ";
	default:
	    snprintf(unknown, sizeof(unknown), "unk: 0x%02x/0x%02x    ", type, code);
	    return unknown;
    }
}

/*
 * Read an IGMP message from the socket
 */
static void igmp_read(int sd, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;
    struct tpacket_auxdata *auxdata;
    struct sockaddr_ll sll = { 0 };
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    char cmbuf[0x100];
    struct iovec iov;
    size_t eth_len;
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
    msg.msg_flags = 0;

    while ((len = recvmsg(sd, &msg, 0)) < 0) {
	if (errno == EINTR)
	    continue;		/* Received signal, retry syscall. */

	logit(LOG_ERR, errno, "Failed recvfrom() in igmp_read()");
	return;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
	    auxdata = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
	    vid = auxdata->tp_vlan_tci & 0x0fff;
	}
    }

    /* The sll.sll_ifindex holds the sender's ifindex */
    eth_len = sizeof(struct ether_header);
    accept_igmp(ifi->ifi_index, recv_buf + eth_len, len - eth_len);
}

/*
 * Process a newly received IGMP packet that is sitting in the input
 * packet buffer.
 */
void accept_igmp(int ifindex, uint8_t *buf, size_t len)
{
    int ipdatalen, iphdrlen, igmpdatalen, timeout, interval = 0, igmp_version = 3;
    uint32_t src, dst, group;
    struct igmp *igmp;
    struct ip *ip;

    if (len < sizeof(struct ip)) {
	logit(LOG_INFO, 0, "received packet too short (%zu bytes) for IP header", len);
	return;
    }

    ip        = (struct ip *)buf;
    src       = ip->ip_src.s_addr;
    dst       = ip->ip_dst.s_addr;

    /*
     * this is most likely a message from the kernel indicating that
     * a new src grp pair message has arrived and so, it would be 
     * necessary to install a route into the kernel for this.
     */
    if (ip->ip_p == 0) {
	if (src != 0 && dst != 0)
	    /* upcall, ignore */
	return;
    }

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ntohs(ip->ip_len) - iphdrlen;

    if ((size_t)(iphdrlen + ipdatalen) != len) {
	logit(LOG_INFO, 0,
	      "received packet from %s shorter (%zu bytes) than hdr+data length (%d+%d)",
	      inet_fmt(src, s1, sizeof(s1)), len, iphdrlen, ipdatalen);
	return;
    }

    igmp        = (struct igmp *)(buf + iphdrlen);
    group       = igmp->igmp_group.s_addr;
    igmpdatalen = ipdatalen - IGMP_MINLEN;
    if (igmpdatalen < 0) {
	logit(LOG_INFO, 0,  "received IP data field too short (%u bytes) for IGMP, from %s",
	      ipdatalen, inet_fmt(src, s1, sizeof(s1)));
	return;
    }

    logit(LOG_DEBUG, 0, "RECV %s from %-15s ifi %-2d to %s",
	  igmp_packet_kind(igmp->igmp_type, igmp->igmp_code),
	  inet_fmt(src, s1, sizeof(s1)), ifindex, inet_fmt(dst, s2, sizeof(s2)));

    switch (igmp->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
	    /* RFC 3376:7.1 */
	    if (ipdatalen == 8) {
		if (igmp->igmp_code == 0)
		    igmp_version = 1;
		else
		    igmp_version = 2;
		timeout = igmp->igmp_code * IGMP_TIMER_SCALE;
	    } else if (ipdatalen >= 12) {
		struct igmpv3_query *query = (struct igmpv3_query *)(buf + iphdrlen);

		igmp_version = 3;
		timeout = igmp_code_time(query->code) / IGMP_TIMER_SCALE;
		interval = igmp_code_time(query->qqic);
	    } else {
		logit(LOG_INFO, 0, "Received invalid IGMP query: Max Resp Code = %d, length = %d",
		      igmp->igmp_code, ipdatalen);
		timeout = 0;
	    }
	    accept_membership_query(ifindex, src, dst, group, interval, timeout, igmp_version);
	    return;

	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
	    accept_group_report(ifindex, src, dst, group, igmp->igmp_type);
	    return;

	case IGMP_V2_LEAVE_GROUP:
	    accept_leave_message(ifindex, src, dst, group);
	    return;

	case IGMP_V3_MEMBERSHIP_REPORT:
	    if (igmpdatalen < IGMP_V3_GROUP_RECORD_MIN_SIZE) {
		logit(LOG_INFO, 0, "Too short IGMP v3 Membership report: igmpdatalen(%d) < MIN(%d)",
		      igmpdatalen, IGMP_V3_GROUP_RECORD_MIN_SIZE);
		return;
	    }
	    accept_membership_report(ifindex, src, dst, (struct igmpv3_report *)(buf + iphdrlen), len - iphdrlen);
	    return;

	default:
	    break;
    }
}

static size_t build_ether(uint8_t *buf, const uint8_t *srcmac, const uint32_t *dst, uint16_t proto)
{
    struct ether_header *eh = (struct ether_header *)buf;

    memset(eh, 0, sizeof(*eh));

    memcpy(eh->ether_shost, srcmac, sizeof(eh->ether_shost));
    ETHER_MAP_IP_MULTICAST(dst, eh->ether_dhost);
    eh->ether_type = htons(proto);

    return sizeof(*eh);
}

static size_t build_vlan(uint8_t *buf, uint16_t vid, uint16_t proto)
{
    struct vlan *v = (struct vlan *)buf;
    uint16_t pcp = 6;
    uint16_t dei = 0;

    v->tci  = htons((pcp << 13) | (dei << 12) | vid);
    v->tpid = htons(proto);

    return sizeof(*v);
}


static size_t build_ipv4(uint8_t *buf, uint32_t src, uint32_t dst, short unsigned int datalen)
{
    struct ip *ip = (struct ip *)(buf);
    size_t len = IP_HEADER_RAOPT_LEN;
    uint8_t *ip_opt;

    ip->ip_v   = IPVERSION;
    ip->ip_hl  = len >> 2;
    ip->ip_tos = 0xc0;		/* Internet Control */
    ip->ip_off = 0;
    ip->ip_ttl = 1;
    ip->ip_p   = IPPROTO_IGMP;

    ip->ip_src.s_addr = src;
    ip->ip_dst.s_addr = dst;
    ip->ip_len        = htons(len + datalen);
    ip->ip_ttl        = 1;

    /*
     *  We don't have anything unique to set this to - for proxy queries,
     * for other queries the kernel will step in and replace zero values
     * in the header anyway. It shouldn't be a problem even for proxy
     * queries though since the packet size is so small that it should
     * hardly be subject to fragmentation.
     */
    ip->ip_id = 0;

    /*
     * RFC2113 IP Router Alert.  Per spec this is required to
     * force certain routers/switches to inspect this frame.
     */
    ip_opt    = buf + sizeof(struct ip);
    ip_opt[0] = IPOPT_RA;
    ip_opt[1] = 4;
    ip_opt[2] = 0;
    ip_opt[3] = 0;

    ip->ip_sum = 0;
    ip->ip_sum = inet_cksum((uint16_t *)buf, len);

    return len;
}

size_t build_query(uint8_t *buf, uint32_t src, uint32_t dst, int type, int qri, int interval,
		   uint32_t group, int datalen)
{
    struct igmpv3_query *igmp = (struct igmpv3_query *)buf;
    size_t igmp_len = IGMP_MINLEN + datalen;
    int code = qri * IGMP_TIMER_SCALE;
    struct ip *ip;

    memset(igmp, 0, igmp_len);

    igmp->type        = type;
    if (datalen >= 4)
        igmp->code    = igmp_floating_point(code);
    else
        igmp->code    = code;
    igmp->group       = group;
    igmp->csum        = 0;

    if (datalen >= 4) {
        igmp->qrv     = igmp_robustness;
        igmp->qqic    = igmp_floating_point(interval);
    }

    /* Note: calculate IGMP checksum last. */
    igmp->csum = inet_cksum((uint16_t *)igmp, igmp_len);

    return igmp_len;
}

/*
 * Construct an IGMP message in the output packet buffer.  The caller may
 * have already placed data in that buffer, of length 'datalen'.
 */
size_t build_igmp(uint8_t *buf, uint32_t src, uint32_t dst, int type, int code, uint32_t group, int datalen)
{
    struct igmp *igmp;
    size_t igmp_len = IGMP_MINLEN + datalen;

    igmp                    = (struct igmp *)buf;
    igmp->igmp_type         = type;
    igmp->igmp_code         = code;
    igmp->igmp_group.s_addr = group;
    igmp->igmp_cksum        = 0;
    igmp->igmp_cksum        = inet_cksum((uint16_t *)igmp, igmp_len);

    return igmp_len;
}

/*
 * Call build_igmp() to build an IGMP message in the output packet buffer.
 * Then send the message from the interface with IP address 'src' to
 * destination 'dst'.
 */
void send_igmp(const struct ifi *ifi, uint32_t dst, int type, int code, uint32_t group, int datalen)
{
    uint32_t src = ifi->ifi_inaddr;
    struct sockaddr_ll sll = { 0 };
    struct ip *ip;
    size_t len;
    int rc;

    memset(send_buf, 0, RECV_BUF_SIZE);

    if (ifi->ifi_vlan) {
	len = build_ether(send_buf, ifi->ifi_hwaddr, &dst, ETH_P_8021Q);
	len += build_vlan(send_buf + len, ifi->ifi_vlan, ETH_P_IP);
    } else
	len = build_ether(send_buf, ifi->ifi_hwaddr, &dst, ETH_P_IP);

    /* Set IP header length,  router-alert is optional */
    ip        = (struct ip *)(send_buf + len);
    ip->ip_hl = IP_HEADER_RAOPT_LEN >> 2;

    len += build_ipv4(send_buf + len, src, dst, IGMP_MINLEN + datalen);

    if (IGMP_MEMBERSHIP_QUERY == type)
	len += build_query(send_buf + len, src, dst, type, code, ifi->ifi_query_interval, group, datalen);
    else
	len += build_igmp(send_buf + len, src, dst, type, code, group, datalen);

    /* Make sure to send in same interface we're receiving */
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifi->ifi_index;

    rc = sendto(ifi->ifi_sock, send_buf, len, 0, (struct sockaddr *)&sll, sizeof(sll));
    if (rc < 0) {
	if (errno == ENETDOWN)
	    iface_check_state();
	else
	    logit(LOG_WARNING, errno, "sendto to %s on %s",
		  inet_fmt(dst, s1, sizeof(s1)), inet_fmt(src, s2, sizeof(s2)));
    }

    logit(LOG_DEBUG, 0, "SENT %s from %-15s to %s", igmp_packet_kind(type, code),
	  src == INADDR_ANY ? "INADDR_ANY" : inet_fmt(src, s1, sizeof(s1)),
	  inet_fmt(dst, s2, sizeof(s2)));
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
