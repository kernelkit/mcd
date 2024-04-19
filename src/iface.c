/* SPDX-License-Identifier: ISC */

#include "defs.h"
#include "inet.h"

/*
 * Private variables.
 */
typedef struct {
    struct listaddr *g;
    int    ifindex;
    int    vid;
    int    delay;
    int    num;
} cbk_t;

extern struct ifaces ifaces;

/*
 * Forward declarations.
 */
static void start_iface        (struct ifi *ifi);
static void stop_iface         (struct ifi *ifi);

static void send_query         (struct ifi *v, uint32_t dst, int code, uint32_t group);
static void query_groups       (int timeout, void *arg);

static void router_timeout_cb  (int timeout, void *arg);

static void delete_group_cb    (int timeout, void *arg);
static int  delete_group_timer (int ifindex, int vid, struct listaddr *g, int tmo);

static void send_query_cb      (int timeout, void *arg);
static int  send_query_timer   (int ifindex, struct listaddr *g, int delay, int num);

static void group_version_cb   (int timeout, void *arg);
static int  group_version_timer(int ifindex, int vid, struct listaddr *g);

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

/*
 * Note: remember to re-init all relevant TAILQ's in iface_init()!
 */
void iface_zero(struct ifi *ifi)
{
    ifi->ifi_flags	= IFIF_DISABLED;
    ifi->ifi_inaddr	= 0;
    ifi->ifi_vlan	= 0;
    ifi->ifi_name[0]	= '\0';
    TAILQ_INIT(&ifi->ifi_static);
    TAILQ_INIT(&ifi->ifi_groups);
    TAILQ_INIT(&ifi->ifi_addrs);
    ifi->ifi_querier	= NULL;
    ifi->ifi_query_interval = igmp_query_interval;
    ifi->ifi_timerid	= 0;
    ifi->ifi_igmpv1_warn = 0;
}

static int is_igmp_proxy(const struct ifi *ifi)
{
    return ifi->ifi_flags & IFIF_PROXY_QUERIER;
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
    in_addr_t curr = 0;
    struct phaddr *pa;

    if (is_igmp_proxy(ifi)) {
	dbg("%s is proxy", ifi->ifi_name);
        if (ifi->ifi_querier && ifi->ifi_querier->al_addr) {
	    dbg("%s has known good querier", ifi->ifi_name);
            return;
	}

        if (ifi->ifi_querier) {
            pev_timer_del(ifi->ifi_querier->al_timerid);
            free(ifi->ifi_querier);
            ifi->ifi_querier = NULL;
        }

	dbg("%s is proxy got elected", ifi->ifi_name);
        goto elected;
    }

    TAILQ_FOREACH(pa, &ifi->ifi_addrs, pa_link) {
	in_addr_t cand = pa->pa_addr;

	dbg("    candidate address %s ...", inet_fmt(cand, s1, sizeof(s1)));
	if (curr) {
	    if (ntohl(cand) >= ntohl(curr))
		continue;
	    if (IN_LINKLOCAL(ntohl(cand)))
		continue;
	}

	curr = cand;
    }

    if (curr != ifi->ifi_inaddr) {
	info("Using %s address %s", ifi->ifi_name, inet_fmt(curr, s1, sizeof(s1)));
	ifi->ifi_inaddr = curr;
    }

    if (curr && ifi->ifi_querier) {
	uint32_t cur = ifi->ifi_querier->al_addr;

	if (ntohl(ifi->ifi_inaddr) < ntohl(cur)) {
	    inet_fmt(cur, s1, sizeof(s1));
	    dbg("New local querier on %s, was %s (%u vs %u)",
		  ifi->ifi_name, s1, ntohl(ifi->ifi_inaddr), ntohl(cur));
	    pev_timer_del(ifi->ifi_querier->al_timerid);
	    free(ifi->ifi_querier);
	    ifi->ifi_querier = NULL;
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
    send_query(ifi, allhosts_group, igmp_response_interval, 0);
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

    /* Check if this is something we're interested in */
    ifi = config_find_ifname(ifname);
    if (!ifi)
	return;

    dbg("Marking %s as now available in system", ifi->ifi_name);
    ifi->ifi_index = ifindex;

    iface_check(ifindex, flags);
}

/*
 * Called by netlink backend
 */
void iface_del(int ifindex, int flags)
{
    struct listaddr *al, *tmp;
    struct phaddr *pa, *pat;
    struct ifi *ifi;

    ifi = config_find_iface(ifindex, 0);
    if (!ifi)
	return;	/* unused in .conf */

    dbg("Marking %s as removed from system", ifi->ifi_name);
    stop_iface(ifi);

    if (ifi->ifi_querier) {
	free(ifi->ifi_querier);
	ifi->ifi_querier = NULL;
    }

    TAILQ_FOREACH_SAFE(al, &ifi->ifi_groups, al_link, tmp) {
	TAILQ_REMOVE(&ifi->ifi_groups, al, al_link);
	free(al);
    }

    TAILQ_FOREACH_SAFE(pa, &ifi->ifi_addrs, pa_link, pat) {
	TAILQ_REMOVE(&ifi->ifi_addrs, pa, pa_link);
	free(pa);
    }

    ifi->ifi_inaddr = 0;
    ifi->ifi_index = 0;
    ifi->ifi_flags |= IFIF_DOWN;
}

/* XXX: refactor to be a callback from config_find_ifname() */
void iface_check(int ifindex, unsigned int flags)
{
    struct ifi *ifi;

    ifi = config_find_iface(ifindex, 0);
    if (!ifi) {
	dbg("Cannot find an active ifindex %d in configuration, skipping ...", ifindex);
	return;
    }

    dbg("Check %s flags 0x%x new flags 0x%x", ifi->ifi_name, ifi->ifi_flags, flags);
    if (ifi->ifi_flags & IFIF_DOWN) {
	if (flags & IFF_UP) {
	    ifi->ifi_flags &= ~IFIF_DOWN;
	    start_iface(ifi);
	}
    } else {
	if (!(flags & IFF_UP)) {
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

static void send_query(struct ifi *ifi, uint32_t dst, int qri, uint32_t group)
{
    int datalen = 4;

    /*
     * IGMP version to send depends on the compatibility mode of the
     * interface:
     *  - IGMPv2: routers MUST send Periodic Queries truncated at the
     *    Group Address field (i.e., 8 bytes long).
     *  - IGMPv1: routers MUST send Periodic Queries with a Max Response
     *    Time of 0
     */
    if (ifi->ifi_flags & IFIF_IGMPV2) {
	datalen = 0;
    } else if (ifi->ifi_flags & IFIF_IGMPV1) {
	datalen = 0;
	qri = 0;
    }

    dbg("Sending %squery on %s src %s",
	  (ifi->ifi_flags & IFIF_IGMPV1) ? "v1 " :
	  (ifi->ifi_flags & IFIF_IGMPV2) ? "v2 " : "v3 ",
	  ifi->ifi_name, inet_name(ifi->ifi_inaddr, 1));

    send_igmp(ifi, dst, IGMP_MEMBERSHIP_QUERY, qri, group, datalen);
}

static void start_iface(struct ifi *ifi)
{
    uint32_t qi = ifi->ifi_query_interval;

    /* Check interface specific settings */
    if (!qi)
	qi = igmp_query_interval;

    igmp_iface_init(ifi);

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

    info("Interface %s now in service", ifi->ifi_name);
}

static void stop_iface(struct ifi *ifi)
{
    struct listaddr *a, *tmp;

    /*
     * Stop query timer
     */
    if (ifi->ifi_timerid > 0)
        pev_timer_del(ifi->ifi_timerid);
    ifi->ifi_timerid = 0;

    /*
     * Discard all group addresses.  (No need to tell kernel;
     * the k_del_iface() call, below, will clean up kernel state.)
     */
    TAILQ_FOREACH_SAFE(a, &ifi->ifi_groups, al_link, tmp) {
	TAILQ_REMOVE(&ifi->ifi_groups, a, al_link);
	free(a);
    }

    dbg("Releasing querier duties on interface %s", ifi->ifi_name);
    ifi->ifi_flags &= ~IFIF_IGMP_QUERIER;

    igmp_iface_exit(ifi);

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
	send_query(ifi, allhosts_group, igmp_response_interval, 0);
}

/*
 * Process an incoming host membership query.  Warn about
 * IGMP version mismatches, perform querier election, and
 * handle group-specific queries when we're not the querier.
 */
void accept_membership_query(int ifindex, int vid, uint32_t src, uint32_t dst,
			     uint32_t group, int intv, int tmo, int ver)
{
    struct ifi *ifi;
    int notnew = 1;

    ifi = config_find_iface(ifindex, vid);
    if (!ifi)
	return;

    /*
     * IGMPv1 + IGMPv2 don't send the query inteval (qqic field only in
     * IGMPv3), assume we are configured correctly to match.
     */
    if (intv == 0)
	intv = ifi->ifi_query_interval;

    if ((ver == 3 && (ifi->ifi_flags & IFIF_IGMPV2)) ||
	(ver == 2 && (ifi->ifi_flags & IFIF_IGMPV1))) {
	int i;

	/*
	 * Exponentially back-off warning rate
	 */
	i = ++ifi->ifi_igmpv1_warn;
	while (i && !(i & 1))
	    i >>= 1;

	if (i == 1) {
	    warnx("Received IGMPv%d query from %s on %s, configured for IGMPv%d", ver,
		  inet_fmt(src, s1, sizeof(s1)), ifi->ifi_name,
		  (ifi->ifi_flags & IFIF_IGMPV1) ? 1 : 2);
	}
    }

    if (ifi->ifi_querier == NULL || ifi->ifi_querier->al_addr != src) {
	uint32_t cur = ifi->ifi_querier ? ifi->ifi_querier->al_addr : ifi->ifi_inaddr;

	/*
	 * This might be:
	 * - A query from a new querier, with a lower source address
	 *   than the current querier (who might be me)
	 * - A query from a new router that just started up and doesn't
	 *   know who the querier is.
	 * - A proxy query (source address 0.0.0.0), never wins elections
	 */
	if (!ntohl(src)) {
	    dbg("Ignoring proxy query on %s", ifi->ifi_name);
	    return;
	}

	if (ntohl(src) < ntohl(cur) || !cur) {
	  again:
	    dbg("New querier %s (was %s) on %s, timeout %d",
		  inet_fmt(src, s1, sizeof(s1)), ifi->ifi_querier
		  ? inet_fmt(ifi->ifi_querier->al_addr, s2, sizeof(s2)) : "me", ifi->ifi_name,
		  router_timeout);

	    if (!ifi->ifi_querier) {
		ifi->ifi_querier = calloc(1, sizeof(struct listaddr));
		if (!ifi->ifi_querier) {
		    err("failed allocating querier");
		    exit(EX_OSERR);
		}

		ifi->ifi_querier->al_timerid = pev_timer_add(router_timeout * 1000000, 0, router_timeout_cb, ifi);
		ifi->ifi_flags &= ~IFIF_IGMP_QUERIER;
	    }

	    time(&ifi->ifi_querier->al_ctime);
	    ifi->ifi_querier->al_addr = src;
	    ifi->ifi_querier->al_interval = intv;
	    notnew = 0;
	} else {
	    if (!ifi->ifi_querier) {
		/*
		 * If we just "won" the election with a link-local
		 * address, go back and fix.  We do not consider a
		 * link-local address better than, e.g., a 192.168.
		 */
		if (IN_LINKLOCAL(ntohl(ifi->ifi_inaddr)) && !IN_LINKLOCAL(ntohl(src)))
		    goto again;
	    }
#if 0
	    dbg("Ignoring query from %s; querier on %s is still %s",
		  inet_fmt(src, s1, sizeof(s1)), ifi->ifi_name,
		  ifi->ifi_querier ? inet_fmt(ifi->ifi_querier->al_addr, s2, sizeof(s2)) : "me");
#endif
	    return;
	}
    }

    /*
     * Reset the timer since we've received a query.
     */
    if (notnew && ifi->ifi_querier && src == ifi->ifi_querier->al_addr) {
	dbg("Resetting query timeout %d sec", router_timeout);
	pev_timer_set(ifi->ifi_querier->al_timerid, router_timeout * 1000000);
	time(&ifi->ifi_querier->al_ctime);
    }

    /*
     * If this is a Group-Specific query which we did not source,
     * we must set our membership timer to [Last Member Query Count] *
     * the [Max Response Time] in the packet.
     */
    if (!(ifi->ifi_flags & (IFIF_IGMPV1|IFIF_IGMP_QUERIER))
	&& group != 0 && src != ifi->ifi_inaddr) {
	struct listaddr *g;

	dbg("Group-specific membership query for %s from %s on %s, timeout %d",
	      inet_fmt(group, s2, sizeof(s2)),
	      inet_fmt(src, s1, sizeof(s1)), ifi->ifi_name, tmo);

	TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	    if (group == g->al_addr && g->al_queryid == 0) {
		if (g->al_timerid > 0)
		    g->al_timerid = pev_timer_del(g->al_timerid);

		if (g->al_queryid > 0)
		    g->al_queryid = pev_timer_del(g->al_queryid);

		/* setup a timeout to remove the group membership */
		g->al_timerid = delete_group_timer(ifindex, vid, g, IGMP_LAST_MEMBER_QUERY_COUNT * tmo);

		dbg("Timer for grp %s on %s set to %d",
		      inet_fmt(group, s2, sizeof(s2)), ifi->ifi_name, pev_timer_get(g->al_timerid) / 1000);
		break;
	    }
	}
    }
}

static void group_debug(struct listaddr *g, char *s, int is_change)
{
    dbg("%sIGMP v%d compatibility mode for group %s",
	  is_change ? "Change to " : "", g->al_pv, s);
}

/*
 * Process an incoming group membership report.
 */
void accept_group_report(int ifindex, int vid, uint32_t src, uint32_t dst, uint32_t group, int r_type)
{
    struct listaddr *g;
    struct ifi *ifi;

    inet_fmt(src, s1, sizeof(s1));
    inet_fmt(dst, s2, sizeof(s2));
    inet_fmt(group, s3, sizeof(s3));

    /* Do not filter LAN scoped groups */
    if (ntohl(group) <= INADDR_MAX_LOCAL_GROUP) { /* group <= 224.0.0.255? */
	dbg("    %-16s LAN scoped group, skipping.", s3);
	return;
    }

    ifi = config_find_iface(ifindex, vid);
    if (!ifi)
	return;

    info("Accepting group membership report: src %s, dst %s, grp %s", s1, s2, s3);

    /*
     * Look for the group in our group list; if found, reset its timer.
     */
    TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	int old_report = 0;

	if (group == g->al_addr) {
	    if (g->al_flags & NBRF_STATIC_GROUP) {
		dbg("Ignoring IGMP JOIN for static group %s on %s.", s3, s1);
		return;
	    }

	    switch (r_type) {
	    case IGMP_V1_MEMBERSHIP_REPORT:
		old_report = 1;
		if (g->al_pv > 1) {
		    g->al_pv = 1;
		    group_debug(g, s3, 1);
		}
		break;

	    case IGMP_V2_MEMBERSHIP_REPORT:
		old_report = 1;
		if (g->al_pv > 2) {
		    g->al_pv = 2;
		    group_debug(g, s3, 1);
		}
		break;

	    default:
		break;
	    }

	    g->al_reporter = src;

	    /** delete old timers, set a timer for expiration **/
	    if (g->al_queryid > 0)
		g->al_queryid = pev_timer_del(g->al_queryid);

	    if (g->al_timerid > 0)
		g->al_timerid = pev_timer_del(g->al_timerid);

	    g->al_timerid = delete_group_timer(ifindex, vid, g, IGMP_GROUP_MEMBERSHIP_INTERVAL);

	    /*
	     * Reset timer for switching version back every time an older
	     * version report is received
	     */
	    if (g->al_pv < 3 && old_report) {
		if (g->al_pv_timerid)
		    g->al_pv_timerid = pev_timer_del(g->al_pv_timerid);

		g->al_pv_timerid = group_version_timer(ifindex, vid, g);
	    }
	    break;
	}
    }

    /*
     * If not found, add it to the list and update kernel cache.
     */
    if (!g) {
	g = calloc(1, sizeof(struct listaddr));
	if (!g) {
	    err("failed allocating group");
	    exit(EX_OSERR);
	}

	g->al_addr = group;

	switch (r_type) {
	case IGMP_V1_MEMBERSHIP_REPORT:
	    g->al_pv = 1;
	    break;

	case IGMP_V2_MEMBERSHIP_REPORT:
	    g->al_pv = 2;
	    break;

	default:
	    g->al_pv = 3;
	    break;
	}

	group_debug(g, s3, 0);

	/** set a timer for expiration **/
        g->al_queryid	= 0;
	g->al_reporter	= src;
	g->al_timerid	= delete_group_timer(ifindex, vid, g, IGMP_GROUP_MEMBERSHIP_INTERVAL);

	/*
	 * Set timer for swithing version back if an older version
	 * report is received
	 */
	if (g->al_pv < 3)
	    g->al_pv_timerid = group_version_timer(ifindex, vid, g);

	TAILQ_INSERT_TAIL(&ifi->ifi_groups, g, al_link);
	time(&g->al_ctime);
    }
}

/*
 * Process an incoming IGMPv2 Leave Group message, an IGMPv3 BLOCK(), or
 * IGMPv3 TO_IN({}) membership report.  Handles older version hosts.
 *
 * We detect IGMPv3 by the dst always being 0.
 */
void accept_leave_message(int ifindex, int vid, uint32_t src, uint32_t dst, uint32_t group)
{
    struct listaddr *g;
    struct ifi *ifi;

    inet_fmt(src, s1, sizeof(s1));
    inet_fmt(group, s3, sizeof(s3));

    ifi = config_find_iface(ifindex, vid);
    if (!ifi)
	return;

    if (!(ifi->ifi_flags & IFIF_IGMP_QUERIER) || (ifi->ifi_flags & IFIF_IGMPV1)) {
	dbg("Ignoring group leave, not querier or interface in IGMPv1 mode.");
	return;
    }

    /*
     * Look for the group in our group list in order to set up a short-timeout
     * query.
     */
    TAILQ_FOREACH(g, &ifi->ifi_groups, al_link) {
	if (group != g->al_addr)
	    continue;

	if (g->al_flags & NBRF_STATIC_GROUP) {
	    dbg("Ignoring IGMP LEAVE for static group %s on %s.", s3, s1);
	    return;
	}

	/* Ignore IGMPv2 LEAVE in IGMPv1 mode, RFC3376, sec. 7.3.2. */
	if (g->al_pv == 1) {
	    dbg("Ignoring IGMP LEAVE for %s on %s, IGMPv1 host exists.", s3, s1);
	    return;
	}

	/* Ignore IGMPv3 BLOCK in IGMPv2 mode, RFC3376, sec. 7.3.2. */
	if (g->al_pv == 2 && dst == 0) {
	    dbg("Ignoring IGMP BLOCK/TO_IN({}) for %s on %s, IGMPv2 host exists.", s3, s1);
	    return;
	}

	/* still waiting for a reply to a query, ignore the leave */
	if (g->al_queryid) {
	    dbg("Ignoring IGMP LEAVE for %s on %s, pending group-specific query.", s3, s1);
	    return;
	}

	/** delete old timer set a timer for expiration **/
	if (g->al_timerid > 0)
	    g->al_timerid = pev_timer_del(g->al_timerid);

	/** send a group specific query **/
	g->al_queryid = send_query_timer(ifi->ifi_index, g, igmp_last_member_interval,
				       IGMP_LAST_MEMBER_QUERY_COUNT);
	g->al_timerid = delete_group_timer(ifindex, vid, g, igmp_last_member_interval
					   * (IGMP_LAST_MEMBER_QUERY_COUNT + 1));

	dbg("Accepted group leave for %s on %s", s3, s1);
	return;
    }

    /*
     * We only get here when we couldn't find the group, or when there
     * still is a group-specific query pending, or when the group is in
     * older version compat, RFC3376.
     */
    dbg("Ignoring IGMP LEAVE/BLOCK for %s on %s, group not found.", s3, s1);
}


/*
 * Loop through and process all sources in a v3 record.
 *
 * Parameters:
 *     r_type   Report type of IGMP message
 *     src      Src address of IGMP message
 *     dst      Multicast group
 *     sources  Pointer to the beginning of sources list in the IGMP message
 *     canary   Pointer to the end of IGMP message
 *
 * Returns:
 *     POSIX OK (0) if succeeded, non-zero on failure.
 */
int accept_sources(int ifindex, int vid, int r_type, uint32_t src, uint32_t dst, uint8_t *sources,
		   uint8_t *canary, int rec_num_sources)
{
    uint8_t *ptr;
    int j;

    for (j = 0, ptr = sources; j < rec_num_sources; ++j, src += 4) {
	struct in_addr *ina = (struct in_addr *)ptr;

        if ((ptr + 4) > canary) {
	    dbg("Invalid IGMPv3 report, too many sources, would overflow.");
            return 1;
        }

	dbg("Add source (%s,%s)", inet_fmt(ina->s_addr, s2, sizeof(s2)),
	      inet_fmt(dst, s1, sizeof(s1)));

        accept_group_report(ifindex, vid, src, ina->s_addr, dst, r_type);
    }

    return 0;
}


/*
 * Handle IGMP v3 membership reports (join/leave)
 */
void accept_membership_report(int ifindex, int vid, uint32_t src, uint32_t dst, struct igmpv3_report *report, ssize_t reportlen)
{
    uint8_t *canary = (uint8_t *)report + reportlen;
    struct igmpv3_grec *record;
    int num_groups, i;

    num_groups = ntohs(report->ngrec);
    if (num_groups < 0) {
	info("Invalid Membership Report from %s: num_groups = %d",
	      inet_fmt(src, s1, sizeof(s1)), num_groups);
	return;
    }

    dbg("IGMP v3 report, %zd bytes, from %s to %s with %d group records.",
	  reportlen, inet_fmt(src, s1, sizeof(s1)), inet_fmt(dst, s2, sizeof(s2)), num_groups);

    record = &report->grec[0];

    for (i = 0; i < num_groups; i++) {
	struct in_addr  rec_group;
	uint8_t        *sources;
	int             rec_type;
	int             rec_auxdatalen;
	int             rec_num_sources;
	int             j, rc;
	int             record_size = 0;

	rec_num_sources = ntohs(record->grec_nsrcs);
	rec_auxdatalen = record->grec_auxwords;
	record_size = sizeof(struct igmpv3_grec) + sizeof(uint32_t) * rec_num_sources + rec_auxdatalen;
	if ((uint8_t *)record + record_size > canary) {
	    info("Invalid group report %p > %p", (uint8_t *)record + record_size, canary);
	    return;
	}

	rec_type = record->grec_type;
	rec_group.s_addr = (in_addr_t)record->grec_mca;
	sources = (uint8_t *)record->grec_src;

	switch (rec_type) {
	case IGMP_MODE_IS_EXCLUDE:
	case IGMP_CHANGE_TO_EXCLUDE_MODE:
	    if (rec_num_sources == 0) {
		/* RFC 5790: TO_EX({}) can be interpreted as a (*,G)
		 *           join, i.e., to include all sources.
		 */
		accept_group_report(ifindex, vid, src, 0, rec_group.s_addr, report->type);
	    } else {
		/* RFC 5790: LW-IGMPv3 does not use TO_EX({x}),
		 *           i.e., filter with non-null source.
		 */
		dbg("IS_EX/TO_EX({x}), not unsupported, RFC5790.");
	    }
	    break;

	case IGMP_MODE_IS_INCLUDE:
	case IGMP_CHANGE_TO_INCLUDE_MODE:
	    if (rec_num_sources == 0) {
		/* RFC5790: TO_IN({}) can be interpreted as an
		 *          IGMPv2 (*,G) leave.
		 */
		accept_leave_message(ifindex, vid, src, 0, rec_group.s_addr);
	    } else {
		/* RFC5790: TO_IN({x}), regular RFC3376 (S,G)
		 *          join with >= 1 source, 'S'.
		 */
		rc = accept_sources(ifindex, vid, report->type, src, rec_group.s_addr,
				    sources, canary, rec_num_sources);
		if (rc)
		    return;
	    }
	    break;

	case IGMP_ALLOW_NEW_SOURCES:
	    /* RFC5790: Same as TO_IN({x}) */
	    rc = accept_sources(ifindex, vid, report->type, src, rec_group.s_addr,
				sources, canary, rec_num_sources);
	    if (rc)
		return;
	    break;

	case IGMP_BLOCK_OLD_SOURCES:
	    /* RFC5790: Instead of TO_EX({x}) */
	    for (j = 0; j < rec_num_sources; j++) {
		uint8_t *gsrc = (uint8_t *)&record->grec_src[j];
		struct in_addr *ina = (struct in_addr *)gsrc;

		if (gsrc > canary) {
		    info("Invalid group record");
		    return;
		}

		dbg("Remove source[%d] (%s,%s)", j,
		      inet_fmt(ina->s_addr, s2, sizeof(s2)), inet_ntoa(rec_group));
		accept_leave_message(ifindex, vid, src, 0, rec_group.s_addr);
	    }
	    break;

	default:
	    /* RFC3376: Unrecognized Record Type values MUST be silently ignored. */
	    break;
	}

	record = (struct igmpv3_grec *)((uint8_t *)record + record_size);
    }
}

/*
 * When an active querier times out we assume the role here.
 */
static void router_timeout_cb(int timeout, void *arg)
{
    struct ifi *ifi = (struct ifi *)arg;

    dbg("Querier %s timed out", inet_fmt(ifi->ifi_querier->al_addr, s1, sizeof(s1)));
    pev_timer_del(ifi->ifi_querier->al_timerid);
    free(ifi->ifi_querier);
    ifi->ifi_querier = NULL;

    ifi->ifi_flags |= IFIF_IGMP_QUERIER;
    send_query(ifi, allhosts_group, igmp_response_interval, 0);
}

/*
 * Time out old version compatibility mode
 */
static void group_version_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid);
    if (!ifi)
	return;

    if (cbk->g->al_pv < 3)
	cbk->g->al_pv++;

    info("Switching IGMP compatibility mode from v%d to v%d for group %s on %s",
	  cbk->g->al_pv - 1, cbk->g->al_pv, inet_fmt(cbk->g->al_addr, s1, sizeof(s1)), ifi->ifi_name);

    if (cbk->g->al_pv < 3)
	pev_timer_set(cbk->g->al_pv_timerid, IGMP_GROUP_MEMBERSHIP_INTERVAL * 1000000);
    else {
	pev_timer_del(cbk->g->al_pv_timerid);
	free(cbk);
    }
}

/*
 * Set a timer to switch version back on an interface.
 */
static int group_version_timer(int ifindex, int vid, struct listaddr *g)
{
    cbk_t *cbk;

    cbk = calloc(1, sizeof(cbk_t));
    if (!cbk) {
	err("failed allocating group timer");
	exit(EX_OSERR);
    }

    cbk->ifindex = ifindex;
    cbk->vid     = vid;
    cbk->g       = g;

    return pev_timer_add(IGMP_GROUP_MEMBERSHIP_INTERVAL * 1000000, 0, group_version_cb, cbk);
}

/*
 * Time out record of a group membership on an interface.
 */
static void delete_group_cb(int timeout, void *arg)
{
    cbk_t *cbk = (cbk_t *)arg;
    struct listaddr *g = cbk->g;
    struct ifi *ifi;

    ifi = config_find_iface(cbk->ifindex, cbk->vid);
    if (!ifi)
	return;

    dbg("Group membership timeout for %s on %s",
	  inet_fmt(cbk->g->al_addr, s1, sizeof(s1)), ifi->ifi_name);

    pev_timer_del(g->al_timerid);

    if (g->al_queryid > 0)
	g->al_queryid = pev_timer_del(g->al_queryid);

    if (g->al_pv_timerid > 0)
	g->al_pv_timerid = pev_timer_del(g->al_pv_timerid);

    TAILQ_REMOVE(&ifi->ifi_groups, g, al_link);
    free(g);
}

/*
 * Set a timer to delete the record of a group membership on an interface.
 */
static int delete_group_timer(int ifindex, int vid, struct listaddr *g, int tmo)
{
    cbk_t *cbk;
    int tid;

    /* cbk is freed as a side effect of pev_timer_del (via the deletion cb) */
    cbk = calloc(1, sizeof(cbk_t));
    if (!cbk) {
	err("failed allocating group timer");
	exit(EX_OSERR);
    }

    cbk->ifindex = ifindex;
    cbk->vid     = vid;
    cbk->g       = g;

    /* Record mtime for IPC "show igmp" */
//    g->al_mtime = virtual_time;

    tid = pev_timer_add(tmo * 1000000, 0, delete_group_cb, cbk);
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

    ifi = config_find_iface(cbk->ifindex, cbk->vid);
    if (!ifi)
	goto end;

    send_query(ifi, cbk->g->al_addr, cbk->delay, cbk->g->al_addr);
    if (--cbk->num > 0) {
	pev_timer_set(cbk->g->al_queryid, cbk->delay * 1000000);
	return;
    }

  end:
    /* we're done, clear us from group */
    cbk->g->al_queryid = pev_timer_del(cbk->g->al_queryid);
    free(cbk);
}

/*
 * Set a timer to send a group-specific query.
 */
static int send_query_timer(int ifindex, struct listaddr *g, int delay, int num)
{
    cbk_t *cbk;

    cbk = calloc(1, sizeof(cbk_t));
    if (!cbk) {
	err("failed allocating query timer");
	exit(EX_OSERR);
    }

    cbk->ifindex = ifindex;
    cbk->g       = g;
    cbk->delay   = delay;
    cbk->num     = num;

    return pev_timer_add(delay * 1000000, 0, send_query_cb, cbk);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
