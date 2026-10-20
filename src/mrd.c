/* SPDX-License-Identifier: ISC */

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include "defs.h"
#include "igmp.h"
#include "inet.h"
#include "mld.h"
#include "mrd.h"

/*
 * Advertisement.  A solicitation or termination is the first 4 bytes
 * but sent at this size, the Linux bridge drops IGMP shorter than its
 * 8 byte header.
 */
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
    uint8_t dmac[ETH_ALEN] = { 0x33, 0x33 };
    struct mrd_msg body = { 0 }, *m;
    inet_addr_t dst;
    size_t len;

    /* Proxy mode, no address to advertise */
    if (inet_addr_is_any(&ifi->ifi_inaddr))
	return;

    body.type = mrd_base(ifi) + msg;
    if (msg == MRD_ADVERT) {
	body.interval = mrd_interval;
	body.qqi = htons(ifi->ifi_query_interval);
	body.qrv = htons(ifi->ifi_compat == GEN_V1 ? 0 : igmp_robustness);
    }

    if (ifi->ifi_family == AF_INET6) {
	const struct in6_addr *src = inet_addr_get6(&ifi->ifi_inaddr);

	inet_addr_set6(&dst, &mrd6_allsnoopers);
	memcpy(&dmac[2], &mrd6_allsnoopers.s6_addr[12], 4);
	len  = build_ether(send_buf, ifi, dmac, ETH_P_IPV6);
	len += build_ipv6(send_buf + len, src, &mrd6_allsnoopers, sizeof(body));
	m = memcpy(send_buf + len, &body, sizeof(body));
	m->csum = icmp6_cksum(src, &mrd6_allsnoopers, m, sizeof(body));
    } else {
	uint32_t src = inet_addr_get4(&ifi->ifi_inaddr);
	uint32_t grp = htonl(INADDR_ALLSNOOPERS_GROUP);

	inet_addr_set4(&dst, grp);
	ETHER_MAP_IP_MULTICAST(&grp, dmac);
	len  = build_ether(send_buf, ifi, dmac, ETH_P_IP);
	len += build_ipv4(send_buf + len, src, grp, sizeof(body));
	m = memcpy(send_buf + len, &body, sizeof(body));
	m->csum = inet_cksum((uint16_t *)m, sizeof(body));
    }
    len += sizeof(body);

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
	next = jitter(mrd_interval * 1000000 - MRD_ADV_JITTER, 2 * MRD_ADV_JITTER);

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

static void router_del(struct ifi *ifi, struct mrd_router *r)
{
    TAILQ_REMOVE(&ifi->ifi_mrd_routers, r, link);
    free(r);
}

/* Forget the routers heard, the interface stops */
void mrd_flush(struct ifi *ifi)
{
    struct mrd_router *r;

    while ((r = TAILQ_FIRST(&ifi->ifi_mrd_routers)))
	router_del(ifi, r);
}

/*
 * Add or refresh a router from its advertisement.  One pass drops the
 * ones not heard from in time, finds this one and counts the rest.
 * It is dead after 3 * (interval + 2.5 % jitter), RFC 4286 section 3.5.
 */
static void router_seen(struct ifi *ifi, const inet_addr_t *src, const void *buf, size_t len)
{
    const struct mrd_msg *m = buf;
    struct mrd_router *r, *tmp, *found = NULL;
    time_t now = time(NULL);
    int n = 0, dead;

    if (len < sizeof(*m) || !m->interval)
	return;

    TAILQ_FOREACH_SAFE(r, &ifi->ifi_mrd_routers, link, tmp) {
	if (r->expires <= now) {
	    dbg("MRD router %s on %s timed out", inet_addr_fmt(&r->addr, s2, sizeof(s2)), ifi->ifi_name);
	    router_del(ifi, r);
	} else if (!inet_addr_cmp(&r->addr, src))
	    found = r;
	else
	    n++;
    }

    r = found;
    if (!r) {
	if (n >= MRD_MAX_ROUTERS)
	    return;

	r = calloc(1, sizeof(*r));
	if (!r)
	    return;

	r->addr = *src;
	TAILQ_INSERT_TAIL(&ifi->ifi_mrd_routers, r, link);
	info("MRD router %s on %s", s1, ifi->ifi_name);
    }

    dead = 3 * m->interval;
    r->interval = m->interval;
    r->qqi      = ntohs(m->qqi);
    r->qrv      = ntohs(m->qrv);
    r->expires  = now + dead + (dead + 39) / 40;
}

static void router_gone(struct ifi *ifi, const inet_addr_t *src)
{
    struct mrd_router *r;

    TAILQ_FOREACH(r, &ifi->ifi_mrd_routers, link) {
	if (inet_addr_cmp(&r->addr, src))
	    continue;

	info("MRD router %s on %s terminated", s1, ifi->ifi_name);
	router_del(ifi, r);
	return;
    }
}

/*
 * Checksum and length are already validated, s1 holds the source.  A
 * solicitation is answered within MaxResponseDelay, unless an
 * advertisement is already on its way, RFC 4286 section 3.4.
 */
void mrd_accept(struct ifi *ifi, int msg, const inet_addr_t *src, const inet_addr_t *dst,
		const void *buf, size_t len)
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

    switch (msg) {
    case MRD_ADVERT:
	if (!inet_addr_cmp(src, &ifi->ifi_inaddr))
	    return;		/* our own */
	router_seen(ifi, src, buf, len);
	break;

    case MRD_TERM:
	router_gone(ifi, src);
	break;

    case MRD_SOLICIT:
	if (ifi->ifi_mrd_timerid <= 0 || ifi->ifi_mrd_pending)
	    return;

	dbg("MRD solicitation from %s on %s, advertising", s1, ifi->ifi_name);
	ifi->ifi_mrd_pending = 1;
	pev_timer_set(ifi->ifi_mrd_timerid, jitter(1, MRD_MAX_RESPONSE_DELAY * 1000000));
	break;
    }
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
