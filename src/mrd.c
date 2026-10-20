/* SPDX-License-Identifier: ISC */

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include "defs.h"
#include "igmp.h"
#include "inet.h"
#include "mld.h"
#include "mrd.h"

/* Advertisement, a solicitation or termination is the first 4 bytes */
struct mrd_msg {
    uint8_t  type;
    uint8_t  interval;		/* AdvertisementInterval, sec            */
    uint16_t csum;
    uint16_t qqi;		/* Querier's Query Interval, sec         */
    uint16_t qrv;		/* Robustness Variable, 0 for IGMPv1     */
};

static const char *mrd_msg_name[] = { "advertisement", "solicitation", "termination" };

static const struct in6_addr mrd6_allsnoopers = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x6a } } };
static const struct in6_addr mrd6_allrouters  = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 } } };

/* base plus a random part below spread, microseconds */
static int jitter(int base, int spread)
{
    return base + rand() % spread;
}

/* The first MRD type of the family, the messages follow in order */
static int mrd_base(const struct ifi *ifi)
{
    return ifi->ifi_family == AF_INET6 ? ICMP6_MRD_ADVERT : IGMP_MRD_ADVERT;
}

/* MRD_ADVERT, MRD_SOLICIT or MRD_TERM, -1 for any other type */
int mrd_msg(const struct ifi *ifi, int type)
{
    int msg = type - mrd_base(ifi);

    return msg >= MRD_ADVERT && msg <= MRD_TERM ? msg : -1;
}

static void send_mrd(const struct ifi *ifi, int msg)
{
    size_t mlen = msg == MRD_ADVERT ? sizeof(struct mrd_msg) : 4;
    uint8_t dmac[ETH_ALEN] = { 0x33, 0x33 };
    struct mrd_msg body = { 0 }, *m;
    inet_addr_t dst;
    size_t len;

    /* Proxy mode, no address to advertise */
    if (inet_addr_is_any(&ifi->ifi_inaddr))
	return;

    body.type = mrd_base(ifi) + msg;
    if (msg == MRD_ADVERT) {
	body.interval = MRD_ADV_INTERVAL;
	body.qqi = htons(ifi->ifi_query_interval);
	body.qrv = htons(ifi->ifi_compat == GEN_V1 ? 0 : igmp_robustness);
    }

    if (ifi->ifi_family == AF_INET6) {
	const struct in6_addr *src = inet_addr_get6(&ifi->ifi_inaddr);

	inet_addr_set6(&dst, &mrd6_allsnoopers);
	memcpy(&dmac[2], &mrd6_allsnoopers.s6_addr[12], 4);
	len  = build_ether(send_buf, ifi, dmac, ETH_P_IPV6);
	len += build_ipv6(send_buf + len, src, &mrd6_allsnoopers, mlen);
	m = memcpy(send_buf + len, &body, mlen);
	m->csum = icmp6_cksum(src, &mrd6_allsnoopers, m, mlen);
    } else {
	uint32_t src = inet_addr_get4(&ifi->ifi_inaddr);
	uint32_t grp = htonl(INADDR_ALLSNOOPERS_GROUP);

	inet_addr_set4(&dst, grp);
	ETHER_MAP_IP_MULTICAST(&grp, dmac);
	len  = build_ether(send_buf, ifi, dmac, ETH_P_IP);
	len += build_ipv4(send_buf + len, src, grp, mlen);
	m = memcpy(send_buf + len, &body, mlen);
	m->csum = inet_cksum((uint16_t *)m, mlen);
    }
    len += mlen;

    inet_addr_fmt(&ifi->ifi_inaddr, s1, sizeof(s1));
    inet_addr_fmt(&dst, s2, sizeof(s2));

    if (sock_send(ifi, len) < 0) {
	warn("sendto %s from %s on %s", s2, s1, ifi->ifi_name);
	return;
    }

    dbg("SENT MRD %s from %s to %s on %s", mrd_msg_name[msg], s1, s2, ifi->ifi_name);
}

/*
 * Advertise, then the next one: the initial ones within
 * MaxInitialAdvertisementInterval, after that every
 * AdvertisementInterval with jitter, RFC 4286 section 3.4.
 */
static void mrd_advert_cb(int timeout, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;
    int next;

    ifi->ifi_mrd_pending = 0;
    send_mrd(ifi, MRD_ADVERT);

    if (++ifi->ifi_mrd_init < MRD_MAX_INITIAL_ADVERTS)
	next = jitter(1, MRD_MAX_INITIAL_INTERVAL * 1000000);
    else
	next = jitter(MRD_ADV_INTERVAL * 1000000 - MRD_ADV_JITTER, 2 * MRD_ADV_JITTER);

    pev_timer_set(ifi->ifi_mrd_timerid, next);
}

void mrd_start(struct ifi *ifi)
{
    if (!(ifi->ifi_flags & IFIF_MRD))
	return;

    if (ifi->ifi_mrd_timerid > 0)
	pev_timer_del(ifi->ifi_mrd_timerid);

    ifi->ifi_mrd_init    = 0;
    ifi->ifi_mrd_pending = 1;
    ifi->ifi_mrd_timerid = pev_timer_add(jitter(1, MRD_MAX_INITIAL_INTERVAL * 1000000), 0,
					 mrd_advert_cb, ifi);
}

/* Called before the interface socket closes, so the termination gets out */
void mrd_stop(struct ifi *ifi)
{
    if (ifi->ifi_mrd_timerid > 0) {
	ifi->ifi_mrd_timerid = pev_timer_del(ifi->ifi_mrd_timerid);
	send_mrd(ifi, MRD_TERM);
    }
    ifi->ifi_mrd_pending = 0;
}

/*
 * Checksum and length are already validated, s1 holds the source.  A
 * solicitation is answered within MaxResponseDelay, unless an
 * advertisement is already on its way, RFC 4286 section 3.4.
 */
void mrd_accept(struct ifi *ifi, int msg, const inet_addr_t *src, const inet_addr_t *dst)
{
    inet_addr_t expect;

    if (ifi->ifi_family == AF_INET6) {
	if (!inet_addr_linklocal(src))
	    return;
	inet_addr_set6(&expect, msg == MRD_SOLICIT ? &mrd6_allrouters : &mrd6_allsnoopers);
    } else
	inet_addr_set4(&expect, msg == MRD_SOLICIT ? allrtrs_group : htonl(INADDR_ALLSNOOPERS_GROUP));

    if (inet_addr_cmp(dst, &expect))
	return;

    if (msg != MRD_SOLICIT) {
	dbg("MRD %s from router %s on %s", mrd_msg_name[msg], s1, ifi->ifi_name);
	return;
    }

    if (ifi->ifi_mrd_timerid <= 0 || ifi->ifi_mrd_pending)
	return;

    dbg("MRD solicitation from %s on %s, advertising", s1, ifi->ifi_name);
    ifi->ifi_mrd_pending = 1;
    pev_timer_set(ifi->ifi_mrd_timerid, jitter(1, MRD_MAX_RESPONSE_DELAY * 1000000));
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
