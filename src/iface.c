/* SPDX-License-Identifier: ISC */

#include "defs.h"
#include "mrd.h"
#include "inet.h"

/*
 * Private variables.
 */
typedef struct {
    struct listaddr *g;
    int    ifindex;
    int    vid;
    int    family;
    int    delay;
    int    num;
} cbk_t;

extern struct ifaces ifaces;

/*
 * Forward declarations.
 */
static void start_iface        (struct ifi *ifi);
static void stop_iface         (struct ifi *ifi);

static void send_query         (struct ifi *ifi, int qri, const inet_addr_t *group);
static void query_groups       (int timeout, void *arg);

static void startup_query_cb   (int timeout, void *arg);
static void startup_query_timer(struct ifi *ifi);

static void router_timeout_cb  (int timeout, void *arg);
static void querier_start      (struct ifi *ifi);

static void delete_group_cb    (int timeout, void *arg);
static int  delete_group_timer (struct ifi *ifi, struct listaddr *g, int tmo);

static void send_query_cb      (int timeout, void *arg);
static int  send_query_timer   (struct ifi *ifi, struct listaddr *g, int delay, int num);

static void group_version_cb   (int timeout, void *arg);
static int  group_version_timer(struct ifi *ifi, struct listaddr *g);

void iface_init(void)
{
    struct ifi *ifi;

    config_iface_init();

    for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
	if (ifi->ifi_flags & IFIF_DOWN) {
	    info("%s is not yet up; skipping", ifi->ifi_name);
	    continue;
	}

	dbg("starting %s; interface now in service", ifi->ifi_name);
	start_iface(ifi);
    }
}

void iface_exit(void)
{
    struct listaddr *a, *tmp;
    struct ifi *ifi, *ifi_tmp;

    /* Deletes the entire list and all sub-lists. */
    TAILQ_FOREACH_SAFE(ifi, &ifaces, ifi_link, ifi_tmp) {
	
	iface_del(ifi->ifi_index, 0);

	TAILQ_FOREACH_SAFE(a, &ifi->ifi_static, al_link, tmp) {
	    TAILQ_REMOVE(&ifi->ifi_static, a, al_link);
	    free(a);
	}
	TAILQ_REMOVE(&ifaces, ifi, ifi_link);
	free(ifi);
    }
}

void iface_lists_init(struct ifi *ifi)
{
    TAILQ_INIT(&ifi->ifi_static);
    TAILQ_INIT(&ifi->ifi_groups);
    TAILQ_INIT(&ifi->ifi_addrs);
    TAILQ_INIT(&ifi->ifi_mrd_routers);
}

void iface_zero(struct ifi *ifi)
{
    ifi->ifi_flags	= IFIF_DISABLED;
    ifi->ifi_family	= AF_INET;
    ifi->ifi_compat	= GEN_V3;
    inet_addr_any(&ifi->ifi_inaddr, ifi->ifi_family);
    ifi->ifi_vlan	= 0;
    ifi->ifi_name[0]	= '\0';
    iface_lists_init(ifi);
    ifi->ifi_querier	= NULL;
    ifi->ifi_query_interval = igmp_query_interval;
    ifi->ifi_timerid	= 0;
    ifi->ifi_startup_timerid = 0;
    ifi->ifi_mrd_timerid = 0;
    ifi->ifi_mrd_init = 0;
    ifi->ifi_mrd_pending = 0;
    ifi->ifi_igmpv1_warn = 0;
}

static int is_igmp_proxy(const struct ifi *ifi)
{
    return ifi->ifi_flags & IFIF_PROXY_QUERIER;
}

const char *iface_proto(const struct ifi *ifi)
{
    return ifi->ifi_family == AF_INET6 ? "MLD" : "IGMP";
}

/*
 * IGMPv1/2/3 and MLDv1/2 share generation numbers 1..3 internally,
 * this gives the version as the protocol itself numbers it.
 */
int iface_pv(const struct ifi *ifi, int pv)
{
    return ifi->ifi_family == AF_INET6 ? pv - 1 : pv;
}

/* The interface's query interval, or the global one, NULL for global */
uint32_t iface_query_interval(const struct ifi *ifi)
{
    return ifi && ifi->ifi_query_interval ? ifi->ifi_query_interval : igmp_query_interval;
}

/*
 * Other querier present interval, RFC 3376 section 8.5 and RFC 3810
 * section 9.5, from the interface's own query interval.  The global
 * default when ifi is NULL, router-timeout overrides both.
 */
uint32_t iface_router_timeout(const struct ifi *ifi)
{
    if (router_timeout)
	return router_timeout;

    return igmp_robustness * iface_query_interval(ifi) + igmp_response_interval / 2;
}

/* Group membership interval, RFC 3376 section 8.4, RFC 3810 section 9.4 */
static uint32_t iface_group_interval(const struct ifi *ifi)
{
    return igmp_robustness * iface_query_interval(ifi) + igmp_response_interval;
}

static void querier_del(struct ifi *ifi)
{
    if (!ifi->ifi_querier)
	return;

    pev_timer_del(ifi->ifi_querier->al_timerid);
    free(ifi->ifi_querier);
    ifi->ifi_querier = NULL;
}

static void group_del(struct ifi *ifi, struct listaddr *g)
{
    pev_timer_del(g->al_timerid);
    pev_timer_del(g->al_queryid);
    pev_timer_del(g->al_pv_timerid);

    TAILQ_REMOVE(&ifi->ifi_groups, g, al_link);
    free(g);
}

/*
 * Restart IGMP Querier election
 *
 * Start by figuring out the best local address for the iface.  Check if
 * the current address is better (RFC), make sure an IPv4LL doesn't win.
 * Usually we want a real address if available.  0.0.0.0 is reserved for
 * proxy querys, which we resort to when we have nothing better and no
 * real querier has been seen.
 */
void iface_check_election(struct ifi *ifi)
{
    inet_addr_t curr;
    struct phaddr *pa;

    inet_addr_any(&curr, ifi->ifi_family);

    if (is_igmp_proxy(ifi)) {
	dbg("%s is proxy", ifi->ifi_name);
        if (ifi->ifi_querier && !inet_addr_is_any(&ifi->ifi_querier->al_addr)) {
	    dbg("%s has known good querier", ifi->ifi_name);
            return;
	}

        querier_del(ifi);

	dbg("%s is proxy got elected", ifi->ifi_name);
        goto elected;
    }

    TAILQ_FOREACH(pa, &ifi->ifi_addrs, pa_link) {
	const inet_addr_t *cand = &pa->pa_addr;

	dbg("    candidate address %s ...", inet_addr_fmt(cand, s1, sizeof(s1)));
	/* MLD queries must have a link-local source, IGMP ones preferably not */
	if (ifi->ifi_family == AF_INET6) {
	    if (!inet_addr_linklocal(cand))
		continue;
	} else if (!inet_addr_is_any(&curr) && inet_addr_linklocal(cand))
	    continue;

	if (!inet_addr_is_any(&curr) && inet_addr_cmp(cand, &curr) >= 0)
	    continue;

	curr = *cand;
    }

    if (inet_addr_cmp(&curr, &ifi->ifi_inaddr)) {
	info("Using %s address %s", ifi->ifi_name, inet_addr_fmt(&curr, s1, sizeof(s1)));
	ifi->ifi_inaddr = curr;
    }

    if (!inet_addr_is_any(&curr) && ifi->ifi_querier) {
	if (inet_addr_cmp(&ifi->ifi_inaddr, &ifi->ifi_querier->al_addr) < 0) {
	    dbg("New local querier on %s, was %s", ifi->ifi_name,
		inet_addr_fmt(&ifi->ifi_querier->al_addr, s1, sizeof(s1)));
	    querier_del(ifi);
	    goto elected;
	}

	/* querier exists and it is better than our best alternative */
	return;
    }
    /* else: no querier exists and we may have a better, or at least proxy */

  elected:
    /*
     * Until (new) neighbors are discovered, assume responsibility for
     * sending periodic group membership queries to the subnet.  Send
     * the first query.
     */
    ifi->ifi_flags |= IFIF_IGMP_QUERIER;
    dbg("Assuming %squerier duties on interface %s",
          is_igmp_proxy(ifi) ? "proxy " : "", ifi->ifi_name);
    querier_start(ifi);
}

/*
 * Called by netlink backend
 */
void iface_add(int ifindex, int flags)
{
    char ifname[IFNAMSIZ];
    struct ifi *ifi;

    if (!if_indextoname(ifindex, ifname))
	return; /* should not happen, but lost (again?) */

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	if (strcmp(ifi->ifi_name, ifname))
	    continue;

	dbg("Marking %s as now available in system", ifi->ifi_name);
	ifi->ifi_index = ifindex;
	config_iface_update(ifi);
    }

    iface_check(ifindex, flags);
}

/*
 * Called by netlink backend
 */
void iface_del(int ifindex, int flags)
{
    struct phaddr *pa, *pat;
    struct ifi *ifi;

    if (!ifindex)
	return;			/* entries not in the system */

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	if (ifi->ifi_index != ifindex)
	    continue;

	dbg("Marking %s as removed from system", ifi->ifi_name);
	if (!(ifi->ifi_flags & IFIF_DOWN))
	    stop_iface(ifi);

	TAILQ_FOREACH_SAFE(pa, &ifi->ifi_addrs, pa_link, pat) {
	    TAILQ_REMOVE(&ifi->ifi_addrs, pa, pa_link);
	    free(pa);
	}

	inet_addr_any(&ifi->ifi_inaddr, ifi->ifi_family);
	ifi->ifi_index = 0;
	ifi->ifi_flags |= IFIF_DOWN;
    }
}

void iface_check(int ifindex, unsigned int flags)
{
    struct ifi *ifi;

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	if (ifi->ifi_index != ifindex)
	    continue;

	dbg("Check %s flags 0x%x new flags 0x%x", ifi->ifi_name, ifi->ifi_flags, flags);
	if (ifi->ifi_flags & IFIF_DOWN) {
	    if (flags & IFF_UP) {
		ifi->ifi_flags &= ~IFIF_DOWN;
		start_iface(ifi);
	    }
	} else if (!(flags & IFF_UP)) {
	    stop_iface(ifi);
	    ifi->ifi_flags |= IFIF_DOWN;
	}
    }
}

/*
 * See if any interfaces have changed from up state to down, or vice versa,
 * including any non-multicast-capable interfaces that are in use as local
 * tunnel end-points.  Ignore interfaces that have been administratively
 * disabled.
 */
void iface_check_state(void)
{
    static int checking_iface = 0;
    struct ifreq ifr;
    struct ifi *ifi;
    int sd;

    if (checking_iface)
	return;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd == -1) {
	err("failed opening temporary socket for SIOCGIFFLAGS");
	exit(EX_OSERR);
    }

    checking_iface = 1;
    for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
	if (ifi->ifi_flags & IFIF_DISABLED)
	    continue;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifi->ifi_name, sizeof(ifr.ifr_name));
	if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
	    if (errno == ENODEV) {
		ifi->ifi_flags  |= IFIF_DISABLED;
		continue;
	    }
	    warn("Failed ioctl SIOCGIFFLAGS for %s", ifr.ifr_name);
	}

	iface_check(ifi->ifi_index, ifr.ifr_flags);
    }

    checking_iface = 0;
    close(sd);
}

static void send_query(struct ifi *ifi, int qri, const inet_addr_t *group)
{
    if (ifi->ifi_family == AF_INET6)
	send_mld_query(ifi, qri, group);
    else
	send_igmp_query(ifi, qri, group);
}

/*
 * Join static groups in the kernel, which then answers queries for
 * them, and track them as groups that never time out or leave.  The
 * kernel memberships are released by sock_reload_end() once a group
 * leaves the configuration.
 */
static void join_static_groups(struct ifi *ifi)
{
    struct listaddr *a, *g;

    if (ifi->ifi_vlan) {
	if (!TAILQ_EMPTY(&ifi->ifi_static))
	    warnx("Static groups not supported in raw VLAN mode, skipping on %s", ifi->ifi_name);
	return;
    }

    TAILQ_FOREACH(a, &ifi->ifi_static, al_link) {
	inet_addr_fmt(&a->al_addr, s1, sizeof(s1));

	if (mcast_join(ifi, &a->al_addr)) {
	    warn("Failed joining static group %s on %s", s1, ifi->ifi_name);
	    continue;
	}

	g = malloc(sizeof(*g));
	if (!g) {
	    err("failed allocating static group");
	    exit(EX_OSERR);
	}

	*g = *a;
	time(&g->al_ctime);
	TAILQ_INSERT_TAIL(&ifi->ifi_groups, g, al_link);

	info("Joined static group %s on %s", s1, ifi->ifi_name);
    }
}

static void start_iface(struct ifi *ifi)
{
    uint32_t qi = iface_query_interval(ifi);

    sock_iface_init(ifi);
    join_static_groups(ifi);

    /*
     * Periodically query for local group memberships.
     */
    if (ifi->ifi_timerid > 0)
	pev_timer_del(ifi->ifi_timerid);
    ifi->ifi_timerid = pev_timer_add(0, qi * 1000000, query_groups, ifi);

    /*
     * Check if we should assume the querier role
     */
    if (!(ifi->ifi_flags & IFIF_DISABLED))
        iface_check_election(ifi);

    mrd_start(ifi);

    info("Interface %s now in service", ifi->ifi_name);
}

static void stop_iface(struct ifi *ifi)
{
    struct listaddr *a, *tmp;

    mrd_stop(ifi);

    /*
     * Stop query timers (periodic, startup burst and topology hold-off)
     */
    if (ifi->ifi_startup_timerid > 0) {
	pev_timer_del(ifi->ifi_startup_timerid);
	ifi->ifi_startup_timerid = 0;
    }
    ifi->ifi_topo_timerid = pev_timer_del(ifi->ifi_topo_timerid);
    ifi->ifi_topo_pending = 0;
    if (ifi->ifi_timerid > 0)
        pev_timer_del(ifi->ifi_timerid);
    ifi->ifi_timerid = 0;

    TAILQ_FOREACH_SAFE(a, &ifi->ifi_groups, al_link, tmp)
	group_del(ifi, a);
    querier_del(ifi);
    mrd_flush(ifi);

    dbg("Releasing querier duties on interface %s", ifi->ifi_name);
    ifi->ifi_flags &= ~IFIF_IGMP_QUERIER;

    sock_iface_exit(ifi);

    info("Interface %s out of service", ifi->ifi_name);
}

/*
 * Send group membership queries on each interface for which I am querier.
 * Note that technically, there should be a timer per interface, as the
 * dynamics of querier election can cause the "right" time to send a
 * query to be different on different interfaces.  However, this simple
 * implementation only ever sends queries sooner than the "right" time,
 * so can not cause loss of membership (but can send more packets than
 * necessary)
 */
static void query_groups(int period, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;

    if (ifi->ifi_flags & (IFIF_DOWN | IFIF_DISABLED))
	return;

    if (ifi->ifi_flags & IFIF_IGMP_QUERIER)
	send_query(ifi, igmp_response_interval, NULL);
}

/*
 * Process an incoming host membership query.  Warn about version
 * mismatches, perform querier election, and handle group-specific
 * queries when we're not the querier.
 */
void accept_membership_query(struct ifi *ifi, const inet_addr_t *src, const inet_addr_t *group,
			     int intv, int tmo, int ver)
{
    uint32_t oqpi = iface_router_timeout(ifi);
    int notnew = 1;

    inet_addr_fmt(src, s1, sizeof(s1));

    /*
     * IGMPv1 + IGMPv2 don't send the query inteval (qqic field only in
     * IGMPv3), assume we are configured correctly to match.
     */
    if (intv == 0)
	intv = ifi->ifi_query_interval;

    if (ver > ifi->ifi_compat) {
	int i;

	/*
	 * Exponentially back-off warning rate
	 */
	i = ++ifi->ifi_igmpv1_warn;
	while (i && !(i & 1))
	    i >>= 1;

	if (i == 1) {
	    warnx("Received %sv%d query from %s on %s, configured for %sv%d",
		  iface_proto(ifi), iface_pv(ifi, ver), s1, ifi->ifi_name, iface_proto(ifi),
		  iface_pv(ifi, ifi->ifi_compat));
	}
    }

    if (ifi->ifi_querier == NULL || inet_addr_cmp(&ifi->ifi_querier->al_addr, src)) {
	const inet_addr_t *cur = ifi->ifi_querier ? &ifi->ifi_querier->al_addr : &ifi->ifi_inaddr;

	/*
	 * This might be:
	 * - A query from a new querier, with a lower source address
	 *   than the current querier (who might be me)
	 * - A query from a new router that just started up and doesn't
	 *   know who the querier is.
	 * - A proxy query (source 0.0.0.0 or ::), never wins elections
	 */
	if (inet_addr_is_any(src)) {
	    dbg("Ignoring proxy query on %s", ifi->ifi_name);
	    return;
	}

	if (inet_addr_cmp(src, cur) < 0 || inet_addr_is_any(cur)) {
	  again:
	    dbg("New querier %s (was %s) on %s, timeout %d", s1, ifi->ifi_querier
		? inet_addr_fmt(&ifi->ifi_querier->al_addr, s2, sizeof(s2)) : "me",
		ifi->ifi_name, oqpi);

	    if (!ifi->ifi_querier) {
		ifi->ifi_querier = calloc(1, sizeof(struct listaddr));
		if (!ifi->ifi_querier) {
		    err("failed allocating querier");
		    exit(EX_OSERR);
		}

		ifi->ifi_querier->al_timerid = pev_timer_add(oqpi * 1000000, 0, router_timeout_cb, ifi);
		ifi->ifi_flags &= ~IFIF_IGMP_QUERIER;
	    }

	    time(&ifi->ifi_querier->al_ctime);
	    ifi->ifi_querier->al_addr = *src;
	    ifi->ifi_querier->al_interval = intv;
	    notnew = 0;
	} else {
	    /*
	     * If we just "won" the election with an IPv4 link-local
	     * address, go back and fix.  We do not consider a
	     * link-local address better than, e.g., a 192.168.
	     */
	    if (!ifi->ifi_querier && ifi->ifi_family == AF_INET &&
		inet_addr_linklocal(&ifi->ifi_inaddr) && !inet_addr_linklocal(src))
		goto again;

	    return;
	}
    }

    /*
     * Reset the timer since we've received a query.
     */
    if (notnew && ifi->ifi_querier && !inet_addr_cmp(src, &ifi->ifi_querier->al_addr)) {
	dbg("Resetting query timeout %d sec", oqpi);
	pev_timer_set(ifi->ifi_querier->al_timerid, oqpi * 1000000);
	time(&ifi->ifi_querier->al_ctime);
    }

    /*
     * If this is a Group-Specific query which we did not source,
     * we must set our membership timer to [Last Member Query Count] *
     * the [Max Response Time] in the packet.
     */
    if (ifi->ifi_compat != GEN_V1 && !(ifi->ifi_flags & IFIF_IGMP_QUERIER)
	&& !inet_addr_is_any(group) && inet_addr_cmp(src, &ifi->ifi_inaddr)) {
	struct listaddr *g;

	dbg("Group-specific membership query for %s from %s on %s, timeout %d",
	    inet_addr_fmt(group, s2, sizeof(s2)), s1, ifi->ifi_name, tmo);

	TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	    if (inet_addr_cmp(group, &g->al_addr) || g->al_queryid != 0)
		continue;

	    if (g->al_timerid > 0)
		g->al_timerid = pev_timer_del(g->al_timerid);

	    /* setup a timeout to remove the group membership */
	    g->al_timerid = delete_group_timer(ifi, g, IGMP_LAST_MEMBER_QUERY_COUNT * tmo);

	    dbg("Timer for grp %s on %s set to %d", s2, ifi->ifi_name,
		pev_timer_get(g->al_timerid) / 1000);
	    break;
	}
    }
}

static void group_debug(const struct ifi *ifi, const struct listaddr *g, const char *s, int is_change)
{
    dbg("%s%s v%d compatibility mode for group %s", is_change ? "Change to " : "",
	iface_proto(ifi), iface_pv(ifi, g->al_pv), s);
}

/*
 * Process an incoming group membership report.  The report generation
 * pv is 1 for IGMPv1, 2 for IGMPv2 and MLDv1, 3 for IGMPv3 and MLDv2.
 */
void accept_group_report(struct ifi *ifi, const inet_addr_t *src, const inet_addr_t *group, int pv)
{
    struct listaddr *g;

    inet_addr_fmt(src, s1, sizeof(s1));
    inet_addr_fmt(group, s3, sizeof(s3));

    if (inet_addr_is_lanscope(group)) {
	dbg("    %-16s LAN scoped group, skipping.", s3);
	return;
    }

    info("Accepting group membership report: src %s, grp %s", s1, s3);

    /*
     * Look for the group in our group list; if found, reset its timer.
     */
    TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	if (inet_addr_cmp(group, &g->al_addr))
	    continue;

	if (g->al_flags & NBRF_STATIC_GROUP) {
	    dbg("Ignoring %s JOIN for static group %s on %s.", iface_proto(ifi), s3, s1);
	    return;
	}

	if (pv < g->al_pv) {
	    g->al_pv = pv;
	    group_debug(ifi, g, s3, 1);
	}

	g->al_reporter = *src;

	/** delete old timers, set a timer for expiration **/
	if (g->al_queryid > 0)
	    g->al_queryid = pev_timer_del(g->al_queryid);

	if (g->al_timerid > 0)
	    g->al_timerid = pev_timer_del(g->al_timerid);

	g->al_timerid = delete_group_timer(ifi, g, iface_group_interval(ifi));

	/*
	 * Reset timer for switching version back every time an older
	 * version report is received
	 */
	if (g->al_pv < 3 && pv < 3) {
	    if (g->al_pv_timerid > 0)
		g->al_pv_timerid = pev_timer_del(g->al_pv_timerid);

	    g->al_pv_timerid = group_version_timer(ifi, g);
	}
	return;
    }

    g = calloc(1, sizeof(struct listaddr));
    if (!g) {
	err("failed allocating group");
	exit(EX_OSERR);
    }

    g->al_addr = *group;
    g->al_pv   = pv;
    group_debug(ifi, g, s3, 0);

    /** set a timer for expiration **/
    g->al_reporter = *src;
    g->al_timerid  = delete_group_timer(ifi, g, iface_group_interval(ifi));

    /*
     * Set timer for swithing version back if an older version
     * report is received
     */
    if (g->al_pv < 3)
	g->al_pv_timerid = group_version_timer(ifi, g);

    TAILQ_INSERT_TAIL(&ifi->ifi_groups, g, al_link);
    time(&g->al_ctime);
}

/*
 * Process an incoming leave: an IGMPv2 Leave, an MLDv1 Done, or a BLOCK
 * or TO_IN({}) record from a v3 generation report, flagged with v3 as
 * older hosts in the group then take precedence, RFC 3376 §7.3.2.
 */
void accept_leave_message(struct ifi *ifi, const inet_addr_t *src, const inet_addr_t *group, int v3)
{
    struct listaddr *g;

    inet_addr_fmt(src, s1, sizeof(s1));
    inet_addr_fmt(group, s3, sizeof(s3));

    if (!(ifi->ifi_flags & IFIF_IGMP_QUERIER) || ifi->ifi_compat == GEN_V1) {
	dbg("Ignoring group leave, not querier or interface in IGMPv1 mode.");
	return;
    }

    /*
     * Look for the group in our group list in order to set up a short-timeout
     * query.
     */
    TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	if (inet_addr_cmp(group, &g->al_addr))
	    continue;

	if (g->al_flags & NBRF_STATIC_GROUP) {
	    dbg("Ignoring %s LEAVE for static group %s on %s.", iface_proto(ifi), s3, s1);
	    return;
	}

	/* Ignore IGMPv2 LEAVE in IGMPv1 mode, RFC3376, sec. 7.3.2. */
	if (g->al_pv == GEN_V1) {
	    dbg("Ignoring LEAVE for %s on %s, IGMPv1 host exists.", s3, s1);
	    return;
	}

	/* Ignore IGMPv3 BLOCK in IGMPv2 mode, RFC3376, sec. 7.3.2. */
	if (g->al_pv == GEN_V2 && v3) {
	    dbg("Ignoring BLOCK/TO_IN({}) for %s on %s, %sv%d host exists.", s3, s1,
		iface_proto(ifi), iface_pv(ifi, GEN_V2));
	    return;
	}

	/* still waiting for a reply to a query, ignore the leave */
	if (g->al_queryid) {
	    dbg("Ignoring LEAVE for %s on %s, pending group-specific query.", s3, s1);
	    return;
	}

	/** delete old timer set a timer for expiration **/
	if (g->al_timerid > 0)
	    g->al_timerid = pev_timer_del(g->al_timerid);

	/** send a group specific query **/
	g->al_queryid = send_query_timer(ifi, g, igmp_last_member_interval,
					 IGMP_LAST_MEMBER_QUERY_COUNT);
	g->al_timerid = delete_group_timer(ifi, g, igmp_last_member_interval
					   * (IGMP_LAST_MEMBER_QUERY_COUNT + 1));

	dbg("Accepted group leave for %s on %s", s3, s1);
	return;
    }

    /*
     * We only get here when we couldn't find the group, or when there
     * still is a group-specific query pending, or when the group is in
     * older version compat, RFC3376.
     */
    dbg("Ignoring LEAVE/BLOCK for %s on %s, group not found.", s3, s1);
}

/*
 * One group record of an IGMPv3 or MLDv2 report, the record types are
 * the same in both.  Source lists are not tracked, RFC 5790 lightweight
 * semantics: a record with sources is a (*,G) join, a BLOCK a leave.
 */
void accept_group_record(struct ifi *ifi, const inet_addr_t *src, const inet_addr_t *group,
			 int type, int nsrcs)
{
    switch (type) {
    case IGMP_MODE_IS_EXCLUDE:
    case IGMP_CHANGE_TO_EXCLUDE_MODE:
	if (nsrcs == 0)
	    accept_group_report(ifi, src, group, GEN_V3);
	else
	    dbg("IS_EX/TO_EX({x}) not supported, RFC 5790.");
	break;

    case IGMP_MODE_IS_INCLUDE:
    case IGMP_CHANGE_TO_INCLUDE_MODE:
	if (nsrcs == 0)
	    accept_leave_message(ifi, src, group, 1);
	else
	    accept_group_report(ifi, src, group, GEN_V3);
	break;

    case IGMP_ALLOW_NEW_SOURCES:
	if (nsrcs)
	    accept_group_report(ifi, src, group, GEN_V3);
	break;

    case IGMP_BLOCK_OLD_SOURCES:
	if (nsrcs)
	    accept_leave_message(ifi, src, group, 1);
	break;

    default:
	/* RFC 3376: Unrecognized Record Type values MUST be silently ignored. */
	break;
    }
}

/*
 * Walk the group records of an IGMPv3 or MLDv2 report, RFC 3376 §4.2
 * and RFC 3810 §5.2: an 8-byte report header, then records with a
 * 4-byte header, the group, and the sources.  Only the address width
 * differs between the two.
 */
void accept_v3_report(struct ifi *ifi, const inet_addr_t *src, const uint8_t *buf, size_t len)
{
    size_t alen = ifi->ifi_family == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
    const uint8_t *ptr = buf + 8, *end = buf + len;
    uint16_t num;
    int i;

    if (len < 8)
	return;

    memcpy(&num, buf + 6, sizeof(num));
    num = ntohs(num);

    dbg("%sv%d report, %zu bytes, from %s with %d group records.", iface_proto(ifi),
	iface_pv(ifi, GEN_V3), len, inet_addr_fmt(src, s1, sizeof(s1)), num);

    for (i = 0; i < num; i++) {
	inet_addr_t group;
	uint16_t nsrcs;
	size_t size;

	if (ptr + 4 + alen > end) {
	    info("Invalid %s report from %s, record %d truncated", iface_proto(ifi), s1, i);
	    return;
	}

	memcpy(&nsrcs, ptr + 2, sizeof(nsrcs));
	nsrcs = ntohs(nsrcs);
	size  = 4 + alen + nsrcs * alen + ptr[1] * 4;
	if (ptr + size > end) {
	    info("Invalid %s report from %s, record %d overflows", iface_proto(ifi), s1, i);
	    return;
	}

	if (alen == sizeof(struct in6_addr)) {
	    inet_addr_set6(&group, (const struct in6_addr *)(ptr + 4));
	} else {
	    uint32_t ina;

	    memcpy(&ina, ptr + 4, sizeof(ina));
	    inet_addr_set4(&group, ina);
	}

	accept_group_record(ifi, src, &group, ptr[0], nsrcs);
	ptr += size;
    }
}

/*
 * Timer context, freed by the timer deletion hook.  Timers look the
 * interface up again when they fire, it may have gone away.
 */
static cbk_t *cbk_new(const struct ifi *ifi, struct listaddr *g)
{
    cbk_t *cbk;

    cbk = calloc(1, sizeof(*cbk));
    if (!cbk) {
	err("failed allocating timer context");
	exit(EX_OSERR);
    }

    cbk->ifindex = ifi->ifi_index;
    cbk->vid     = ifi->ifi_vlan;
    cbk->family  = ifi->ifi_family;
    cbk->g       = g;

    return cbk;
}

/*
 * RFC3376 §8.6/§8.7: Send remaining startup queries at Startup Query Interval.
 * Called once per fire; re-arms itself until the count reaches zero.
 */
static void startup_query_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid, cbk->family);
    if (!ifi || !(ifi->ifi_flags & IFIF_IGMP_QUERIER))
	goto end;

    send_query(ifi, igmp_response_interval, NULL);
    if (--cbk->num > 0) {
	pev_timer_set(ifi->ifi_startup_timerid, cbk->delay * 1000000);
	return;
    }

end:
    if (ifi)
	ifi->ifi_startup_timerid = pev_timer_del(ifi->ifi_startup_timerid);
}

/*
 * Schedule the startup query burst: igmp_robustness - 1 additional queries
 * (the first was already sent) at Startup Query Interval (Query Interval / 4).
 */
static void startup_query_timer(struct ifi *ifi)
{
    uint32_t qi = iface_query_interval(ifi);
    uint32_t sqi = qi / 4 > 0 ? qi / 4 : 1;
    cbk_t *cbk;

    if (igmp_robustness <= 1)
	return;

    cbk = cbk_new(ifi, NULL);
    cbk->num     = igmp_robustness - 1;
    cbk->delay   = sqi;

    if (ifi->ifi_startup_timerid > 0)
	pev_timer_del(ifi->ifi_startup_timerid);

    ifi->ifi_startup_timerid = pev_timer_add(sqi * 1000000, 0, startup_query_cb, cbk);
    pev_timer_set_cb_del(ifi->ifi_startup_timerid, free);
}

/*
 * Become querier: first general query and the RFC 3376 §8.6, §8.7
 * startup query burst.
 */
static void querier_start(struct ifi *ifi)
{
    send_query(ifi, igmp_response_interval, NULL);
    startup_query_timer(ifi);
}

static void topo_holdoff_cb(int timeout, void *arg);

/*
 * Topology query, then one second of hold-off so a flapping port
 * gets one query per second.
 */
static void topo_query(struct ifi *ifi)
{
    ifi->ifi_topo_pending = 0;
    querier_start(ifi);

    if (ifi->ifi_topo_timerid > 0)
	pev_timer_set(ifi->ifi_topo_timerid, 1000000);
    else
	ifi->ifi_topo_timerid = pev_timer_add(1000000, 0, topo_holdoff_cb, ifi);
}

static void topo_holdoff_cb(int timeout, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;

    if (ifi->ifi_topo_pending && (ifi->ifi_flags & IFIF_IGMP_QUERIER))
	topo_query(ifi);
    else
	ifi->ifi_topo_timerid = pev_timer_del(ifi->ifi_topo_timerid);
}

/*
 * A port of the bridge started forwarding: link up, STP settled or
 * port added.  Hosts behind it are not in the MDB until they answer
 * a query, so send one now rather than at the next query interval,
 * RFC 4541 section 2.1.1.  Our interface is the bridge itself or a
 * vlan interface on top of it.
 */
void iface_topology_change(int bridge, int port)
{
    struct ifi *ifi;

    if (!topology_query)
	return;

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	char ifname[IFNAMSIZ];

	if (ifi->ifi_index != bridge && ifi->ifi_lower != bridge)
	    continue;
	if (ifi->ifi_flags & (IFIF_DOWN | IFIF_DISABLED))
	    continue;
	if (!(ifi->ifi_flags & IFIF_IGMP_QUERIER))
	    continue;

	if (ifi->ifi_topo_timerid > 0) {
	    ifi->ifi_topo_pending = 1;
	    continue;
	}

	info("Port %s forwarding, sending query on %s",
	     if_indextoname(port, ifname) ?: "?", ifi->ifi_name);
	topo_query(ifi);
    }
}

/*
 * When an active querier times out we assume the role here.
 */
static void router_timeout_cb(int timeout, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;

    dbg("Querier %s timed out", inet_addr_fmt(&ifi->ifi_querier->al_addr, s1, sizeof(s1)));
    querier_del(ifi);

    ifi->ifi_flags |= IFIF_IGMP_QUERIER;
    querier_start(ifi);
}

/*
 * Time out old version compatibility mode
 */
static void group_version_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid, cbk->family);
    if (!ifi)
	return;

    if (cbk->g->al_pv < 3)
	cbk->g->al_pv++;

    info("Switching %s compatibility mode from v%d to v%d for group %s on %s", iface_proto(ifi),
	 iface_pv(ifi, cbk->g->al_pv - 1), iface_pv(ifi, cbk->g->al_pv),
	 inet_addr_fmt(&cbk->g->al_addr, s1, sizeof(s1)), ifi->ifi_name);

    if (cbk->g->al_pv < 3)
	pev_timer_set(cbk->g->al_pv_timerid, iface_group_interval(ifi) * 1000000);
    else
	cbk->g->al_pv_timerid = pev_timer_del(cbk->g->al_pv_timerid);
}

/*
 * Set a timer to switch version back on an interface.
 */
static int group_version_timer(struct ifi *ifi, struct listaddr *g)
{
    int tid;

    tid = pev_timer_add(iface_group_interval(ifi) * 1000000, 0, group_version_cb, cbk_new(ifi, g));
    pev_timer_set_cb_del(tid, free);

    return tid;
}

/*
 * Time out record of a group membership on an interface.
 */
static void delete_group_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct listaddr *g = cbk->g;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid, cbk->family);
    if (!ifi)
	return;

    dbg("Group membership timeout for %s on %s",
	inet_addr_fmt(&cbk->g->al_addr, s1, sizeof(s1)), ifi->ifi_name);

    group_del(ifi, g);
}

/*
 * Set a timer to delete the record of a group membership on an interface.
 */
static int delete_group_timer(struct ifi *ifi, struct listaddr *g, int tmo)
{
    int tid;

    tid = pev_timer_add(tmo * 1000000, 0, delete_group_cb, cbk_new(ifi, g));
    pev_timer_set_cb_del(tid, free);

    return tid;
}

/*
 * Send a group-specific query.
 */
static void send_query_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid, cbk->family);
    if (!ifi)
	goto end;

    send_query(ifi, cbk->delay, &cbk->g->al_addr);
    if (--cbk->num > 0) {
	pev_timer_set(cbk->g->al_queryid, cbk->delay * 1000000);
	return;
    }

  end:
    /* we're done, clear us from group */
    cbk->g->al_queryid = pev_timer_del(cbk->g->al_queryid);
}

/*
 * Set a timer to send a group-specific query.
 */
static int send_query_timer(struct ifi *ifi, struct listaddr *g, int delay, int num)
{
    cbk_t *cbk = cbk_new(ifi, g);
    int tid;

    cbk->delay = delay;
    cbk->num   = num;

    tid = pev_timer_add(delay * 1000000, 0, send_query_cb, cbk);
    pev_timer_set_cb_del(tid, free);

    return tid;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
