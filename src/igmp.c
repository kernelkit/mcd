/* SPDX-License-Identifier: ISC */

#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include "defs.h"
#include "igmp.h"
#include "inet.h"

/*
 * Exported variables.
 */
int             router_alert;		     /* IP option Router Alert      */
int             topology_query;		     /* Query when a port comes up  */
uint32_t        router_timeout;		     /* Other querier present intv. */
uint32_t	igmp_query_interval;	     /* Default: 125 sec            */
uint32_t	igmp_response_interval;	     /* Default: 10 sec             */
uint32_t	igmp_last_member_interval;   /* Default: 1                  */
uint32_t	igmp_robustness;	     /* Default: 2                  */
uint32_t	allhosts_group;		     /* All hosts addr in net order */
uint32_t	allrtrs_group;		     /* All-Routers "  in net order */
uint32_t	allreports_group;	     /* IGMPv3 member reports       */

void igmp_init(void)
{
    allhosts_group   = htonl(INADDR_ALLHOSTS_GROUP);
    allrtrs_group    = htonl(INADDR_ALLRTRS_GROUP);
    allreports_group = htonl(INADDR_ALLRPTS_GROUP);

    igmp_query_interval       = IGMP_QUERY_INTERVAL_DEFAULT;
    igmp_response_interval    = IGMP_QUERY_RESPONSE_INTERVAL;
    igmp_last_member_interval = IGMP_LAST_MEMBER_INTERVAL_DEFAULT;
    igmp_robustness           = IGMP_ROBUSTNESS_DEFAULT;
    router_timeout            = 0; /* unset, see config_init() */
    router_alert              = 1;
    topology_query            = 1;
}

static const char *igmp_packet_kind(uint8_t type)
{
    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:		return "membership query  ";
    case IGMP_V1_MEMBERSHIP_REPORT:	return "v1 member report  ";
    case IGMP_V2_MEMBERSHIP_REPORT:	return "v2 member report  ";
    case IGMP_V3_MEMBERSHIP_REPORT:	return "v3 member report  ";
    case IGMP_V2_LEAVE_GROUP:		return "leave message     ";
    default:				return NULL;
    }
}

/*
 * Process a received IGMP packet.
 */
void accept_igmp(struct ifi *ifi, int vid, uint8_t *buf, size_t len)
{
    int ipdatalen, iphdrlen, igmpdatalen, timeout, interval = 0, ver = GEN_V3;
    inet_addr_t src, group;
    const char *kind;
    struct igmp *igmp;
    struct ip *ip;

    if (len < sizeof(struct ip)) {
	info("received packet too short (%zu bytes) for IP header", len);
	return;
    }

    ip = (struct ip *)buf;
    inet_addr_set4(&src, ip->ip_src.s_addr);
    inet_addr_fmt(&src, s1, sizeof(s1));

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ntohs(ip->ip_len) - iphdrlen;

    if ((size_t)(iphdrlen + ipdatalen) > len) {
	info("received packet from %s shorter (%zu bytes) than hdr+data length (%d+%d)",
	     s1, len, iphdrlen, ipdatalen);
	return;
    }

    igmp        = (struct igmp *)(buf + iphdrlen);
    igmpdatalen = ipdatalen - IGMP_MINLEN;
    if (igmpdatalen < 0) {
	info("received IP data field too short (%u bytes) for IGMP, from %s", ipdatalen, s1);
	return;
    }

    kind = igmp_packet_kind(igmp->igmp_type);
    if (!kind)
	return;

    dbg("RECV %s from %-15s ifi %-2d.%d to %s", kind, s1, ifi->ifi_index, vid,
	inet_fmt(ip->ip_dst.s_addr, s2, sizeof(s2)));

    inet_addr_set4(&group, igmp->igmp_group.s_addr);

    switch (igmp->igmp_type) {
    case IGMP_MEMBERSHIP_QUERY:
	/* RFC 3376:7.1 */
	if (ipdatalen == 8) {
	    ver = igmp->igmp_code == 0 ? GEN_V1 : GEN_V2;
	    timeout = igmp->igmp_code * IGMP_TIMER_SCALE;
	} else if (ipdatalen >= 12) {
	    struct igmpv3_query *query = (struct igmpv3_query *)igmp;

	    timeout  = igmp_code_time(query->code) / IGMP_TIMER_SCALE;
	    interval = igmp_code_time(query->qqic);
	} else {
	    info("Received invalid IGMP query: Max Resp Code = %d, length = %d",
		 igmp->igmp_code, ipdatalen);
	    timeout = 0;
	}
	accept_membership_query(ifi, &src, &group, interval, timeout, ver);
	break;

    case IGMP_V1_MEMBERSHIP_REPORT:
	accept_group_report(ifi, &src, &group, GEN_V1);
	break;

    case IGMP_V2_MEMBERSHIP_REPORT:
	accept_group_report(ifi, &src, &group, GEN_V2);
	break;

    case IGMP_V2_LEAVE_GROUP:
	accept_leave_message(ifi, &src, &group, 0);
	break;

    case IGMP_V3_MEMBERSHIP_REPORT:
	accept_v3_report(ifi, &src, (uint8_t *)igmp, ipdatalen);
	break;
    }
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

static size_t build_query(uint8_t *buf, int qri, int interval, uint32_t group, int datalen)
{
    struct igmpv3_query *igmp = (struct igmpv3_query *)buf;
    size_t igmp_len = IGMP_MINLEN + datalen;
    int code = qri * IGMP_TIMER_SCALE;

    memset(igmp, 0, igmp_len);

    igmp->type  = IGMP_MEMBERSHIP_QUERY;
    igmp->group = group;
    if (datalen >= 4) {
        igmp->code = igmp_floating_point(code);
        igmp->qrv  = igmp_robustness;
        igmp->qqic = igmp_floating_point(interval);
    } else
        igmp->code = code;

    /* Note: calculate IGMP checksum last. */
    igmp->csum = inet_cksum((uint16_t *)igmp, igmp_len);

    return igmp_len;
}

/*
 * Send a General Query, or a Group-Specific one when group is set.
 * IGMPv2 routers send queries truncated after the group field, IGMPv1
 * ones with Max Response Time zero, RFC 2236 §2 and RFC 3376 §7.
 */
void send_igmp_query(const struct ifi *ifi, int qri, const inet_addr_t *group)
{
    uint32_t src = inet_addr_get4(&ifi->ifi_inaddr);
    uint32_t grp = group ? inet_addr_get4(group) : 0;
    uint32_t dst = group ? grp : allhosts_group;
    uint8_t dmac[ETH_ALEN];
    int datalen = 4;
    size_t len;

    if (ifi->ifi_compat == GEN_V2) {
	datalen = 0;
    } else if (ifi->ifi_compat == GEN_V1) {
	datalen = 0;
	qri = 0;
    }

    ETHER_MAP_IP_MULTICAST(&dst, dmac);
    len  = build_ether(send_buf, ifi, dmac, ETH_P_IP);
    len += build_ipv4(send_buf + len, src, dst, IGMP_MINLEN + datalen);
    len += build_query(send_buf + len, qri, ifi->ifi_query_interval, grp, datalen);

    inet_fmt(src, s1, sizeof(s1));
    inet_fmt(dst, s2, sizeof(s2));

    if (sock_send(ifi, len) < 0) {
	warn("sendto %s from %s on %s", s2, s1, ifi->ifi_name);
	return;
    }

    dbg("SENT IGMPv%d membership query from %s to %s on %s", ifi->ifi_compat, s1, s2, ifi->ifi_name);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
