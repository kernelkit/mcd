/* SPDX-License-Identifier: ISC */

#include <net/ethernet.h>
#include <netinet/ip6.h>

#include "defs.h"
#include "inet.h"
#include "mld.h"
#include "mrd.h"

static const struct in6_addr mld_allnodes = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };

/* Hop-by-hop header with the Router Alert option, RFC 2711 */
struct mld_hbh {
    struct ip6_hbh        hdr;
    struct ip6_opt_router ra;
    uint8_t               pad[2];
};

/*
 * MLDv2 Maximum Response Code, RFC 3810 §5.1.3: milliseconds below
 * 32768, above that a 3-bit exponent and 12-bit mantissa.
 */
static uint16_t mld_mrc_code(unsigned int ms)
{
    unsigned int exp, mant = 0;

    if (ms < 32768)
	return ms;

    for (exp = 0; exp < 8; exp++) {
	mant = ms >> (exp + 3);
	if (mant < 0x2000)
	    break;
    }
    if (exp == 8)
	return 0xffff;

    return 0x8000 | (exp << 12) | (mant & 0xfff);
}

static unsigned int mld_mrc_time(uint16_t code)
{
    if (code < 32768)
	return code;

    return ((code & 0xfff) | 0x1000) << (((code >> 12) & 7) + 3);
}

/*
 * ICMPv6 checksum over the pseudo header and message, RFC 8200 §8.1.
 * One's complement sums are associative, so the two parts are summed
 * separately and folded together.
 */
uint16_t icmp6_cksum(const struct in6_addr *src, const struct in6_addr *dst,
		     const void *msg, size_t len)
{
    struct {
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t plen;
	uint8_t  zero[3];
	uint8_t  nxt;
    } ph;
    uint32_t sum;

    memset(&ph, 0, sizeof(ph));
    ph.src  = *src;
    ph.dst  = *dst;
    ph.plen = htonl(len);
    ph.nxt  = IPPROTO_ICMPV6;

    sum  = (uint16_t)~inet_cksum((uint16_t *)&ph, sizeof(ph));
    sum += (uint16_t)~inet_cksum((uint16_t *)msg, len);
    sum  = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static const char *mld_packet_kind(uint8_t type)
{
    switch (type) {
    case MLD_LISTENER_QUERY:	 return "listener query    ";
    case MLD_LISTENER_REPORT:	 return "v1 listener report";
    case MLD_LISTENER_REDUCTION: return "listener done     ";
    case MLDV2_LISTENER_REPORT:	 return "v2 listener report";
    case ICMP6_MRD_ADVERT:	 return "mrd advertisement ";
    case ICMP6_MRD_ADVERT + 1:	 return "mrd solicitation  ";
    case ICMP6_MRD_ADVERT + 2:	 return "mrd termination   ";
    default:			 return NULL;
    }
}

/*
 * Process a received MLD packet, hop-by-hop options precede ICMPv6 as
 * RFC 2710 §3 requires the Router Alert option.
 */
void accept_mld(struct ifi *ifi, int vid, uint8_t *buf, size_t len)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
    inet_addr_t src, group;
    struct mld_hdr *mld;
    const char *kind;
    size_t off, plen;
    uint8_t nxt;
    int msg;

    if (len < sizeof(*ip6)) {
	info("received packet too short (%zu bytes) for IPv6 header", len);
	return;
    }

    plen = ntohs(ip6->ip6_plen);
    if (sizeof(*ip6) + plen > len) {
	info("received IPv6 packet shorter (%zu bytes) than header+payload length (%zu)",
	     len, sizeof(*ip6) + plen);
	return;
    }

    nxt = ip6->ip6_nxt;
    off = sizeof(*ip6);
    if (nxt == IPPROTO_HOPOPTS) {
	struct ip6_hbh *hbh = (struct ip6_hbh *)(buf + off);
	size_t hlen;

	if (plen < sizeof(*hbh))
	    return;

	hlen = (hbh->ip6h_len + 1) * 8;
	if (hlen > plen)
	    return;

	nxt   = hbh->ip6h_nxt;
	off  += hlen;
	plen -= hlen;
    }

    if (nxt != IPPROTO_ICMPV6 || plen < sizeof(struct icmp6_hdr))
	return;

    mld  = (struct mld_hdr *)(buf + off);
    kind = mld_packet_kind(mld->mld_type);
    if (!kind)
	return;			/* other ICMPv6, e.g. router solicitations */

    inet_addr_set6(&src, &ip6->ip6_src);
    inet_addr_fmt(&src, s1, sizeof(s1));

    if (icmp6_cksum(&ip6->ip6_src, &ip6->ip6_dst, mld, plen)) {
	info("received MLD packet with bad checksum from %s", s1);
	return;
    }

    dbg("RECV %s from %s ifi %-2d.%d to %s", kind, s1, ifi->ifi_index, vid,
	inet_ntop(AF_INET6, &ip6->ip6_dst, s2, sizeof(s2)));

    msg = mrd_msg(ifi, mld->mld_type);
    if (msg >= 0) {
	inet_addr_t dst;

	inet_addr_set6(&dst, &ip6->ip6_dst);
	mrd_accept(ifi, msg, &src, &dst);
	return;
    }

    if (mld->mld_type == MLDV2_LISTENER_REPORT) {
	accept_v3_report(ifi, &src, (uint8_t *)mld, plen);
	return;
    }

    if (plen < sizeof(*mld)) {
	info("Received invalid MLD message from %s, length = %zu", s1, plen);
	return;
    }
    inet_addr_set6(&group, &mld->mld_addr);

    switch (mld->mld_type) {
    case MLD_LISTENER_QUERY:
	if (plen == sizeof(*mld)) {
	    accept_membership_query(ifi, &src, &group, 0, ntohs(mld->mld_maxdelay) / 1000, GEN_V2);
	} else if (plen >= sizeof(struct mldv2_query)) {
	    struct mldv2_query *query = (struct mldv2_query *)mld;

	    accept_membership_query(ifi, &src, &group, igmp_code_time(query->qqic),
				    mld_mrc_time(ntohs(query->mrc)) / 1000, GEN_V3);
	} else
	    info("Received invalid MLD query from %s, length = %zu", s1, plen);
	break;

    case MLD_LISTENER_REPORT:
	accept_group_report(ifi, &src, &group, GEN_V2);
	break;

    case MLD_LISTENER_REDUCTION:
	accept_leave_message(ifi, &src, &group, 0);
	break;
    }
}

/*
 * IPv6 header and the hop-by-hop header with the Router Alert option,
 * RFC 2711, for an ICMPv6 message of datalen bytes.
 */
size_t build_ipv6(uint8_t *buf, const struct in6_addr *src, const struct in6_addr *dst, size_t datalen)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
    struct mld_hbh *hbh = (struct mld_hbh *)(ip6 + 1);

    memset(hbh, 0, sizeof(*hbh));
    hbh->hdr.ip6h_nxt  = IPPROTO_ICMPV6;
    hbh->ra.ip6or_type = IP6OPT_ROUTER_ALERT;
    hbh->ra.ip6or_len  = sizeof(hbh->ra.ip6or_value);
    hbh->pad[0]        = IP6OPT_PADN;

    memset(ip6, 0, sizeof(*ip6));
    ip6->ip6_flow = htonl(6U << 28);
    ip6->ip6_plen = htons(sizeof(*hbh) + datalen);
    ip6->ip6_nxt  = IPPROTO_HOPOPTS;
    ip6->ip6_hlim = 1;
    ip6->ip6_src  = *src;
    ip6->ip6_dst  = *dst;

    return sizeof(*ip6) + sizeof(*hbh);
}

/*
 * Send a General Query, or a Group-Specific one when group is set, as
 * MLDv1 or MLDv2 depending on the interface compatibility mode.
 */
void send_mld_query(const struct ifi *ifi, int qri, const inet_addr_t *group)
{
    const struct in6_addr *dst = group ? inet_addr_get6(group) : &mld_allnodes;
    const struct in6_addr *src = inet_addr_get6(&ifi->ifi_inaddr);
    uint8_t dmac[ETH_ALEN] = { 0x33, 0x33 };
    struct mldv2_query *query;
    size_t len, qlen;

    memcpy(&dmac[2], &dst->s6_addr[12], 4);
    qlen = ifi->ifi_compat == GEN_V2 ? sizeof(struct mld_hdr) : sizeof(*query);

    len  = build_ether(send_buf, ifi, dmac, ETH_P_IPV6);
    len += build_ipv6(send_buf + len, src, dst, qlen);
    query = (struct mldv2_query *)(send_buf + len);

    memset(query, 0, qlen);
    query->type = MLD_LISTENER_QUERY;
    if (group)
	query->group = *dst;

    if (ifi->ifi_compat == GEN_V2) {
	query->mrc = htons(qri * 1000);
    } else {
	query->mrc  = htons(mld_mrc_code(qri * 1000));
	query->qrv  = igmp_robustness & 7;
	query->qqic = igmp_floating_point(ifi->ifi_query_interval);
    }
    query->csum = icmp6_cksum(src, dst, query, qlen);
    len += qlen;

    inet_ntop(AF_INET6, src, s1, sizeof(s1));
    inet_ntop(AF_INET6, dst, s2, sizeof(s2));

    if (sock_send(ifi, len) < 0) {
	warn("sendto %s from %s on %s", s2, s1, ifi->ifi_name);
	return;
    }

    dbg("SENT MLDv%d listener query from %s to %s on %s", iface_pv(ifi, ifi->ifi_compat),
	s1, s2, ifi->ifi_name);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
