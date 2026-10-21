/* SPDX-License-Identifier: ISC */

#include "defs.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include <net/if.h>

static int id;
static int sd;

/* Bridge ports seen, to tell a change of state from a repeat */
struct port {
    TAILQ_ENTRY(port) link;
    int ifindex;
    int state;
};

static TAILQ_HEAD(, port) ports = TAILQ_HEAD_INITIALIZER(ports);

struct link {
    int lower;		/* IFLA_LINK, the interface below a vlan     */
    int master;		/* IFLA_MASTER, the bridge of a port         */
    int state;		/* IFLA_BRPORT_STATE, in AF_BRIDGE messages  */
};

static void link_attrs(struct nlmsghdr *nlh, struct link *l)
{
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int len = IFLA_PAYLOAD(nlh);

    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
	switch (rta->rta_type & NLA_TYPE_MASK) {
	case IFLA_LINK:
	    l->lower = *(int *)RTA_DATA(rta);
	    break;

	case IFLA_MASTER:
	    l->master = *(int *)RTA_DATA(rta);
	    break;

	case IFLA_PROTINFO:
	    if (ifi->ifi_family == AF_BRIDGE) {
		struct rtattr *sub = RTA_DATA(rta);
		int sublen = RTA_PAYLOAD(rta);

		for (; RTA_OK(sub, sublen); sub = RTA_NEXT(sub, sublen)) {
		    if (sub->rta_type == IFLA_BRPORT_STATE)
			l->state = *(uint8_t *)RTA_DATA(sub);
		}
	    }
	    break;
	}
    }
}

static struct port *port_find(int ifindex)
{
    struct port *p;

    TAILQ_FOREACH(p, &ports, link) {
	if (p->ifindex == ifindex)
	    return p;
    }

    return NULL;
}

static void port_del(int ifindex)
{
    struct port *p = port_find(ifindex);

    if (p) {
	TAILQ_REMOVE(&ports, p, link);
	free(p);
    }
}

/*
 * Remember the state of a bridge port, report when it starts
 * forwarding: link up, STP settled, or port added to the bridge.
 */
static void port_state(int ifindex, int master, int state)
{
    struct port *p = port_find(ifindex);

    if (!p) {
	p = calloc(1, sizeof(*p));
	if (!p)
	    return;

	p->ifindex = ifindex;
	p->state = -1;
	TAILQ_INSERT_TAIL(&ports, p, link);
    }

    if (state == p->state)
	return;
    p->state = state;

    if (state == BR_STATE_FORWARDING)
	iface_topology_change(master, ifindex);
}

static void link_msg(struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    struct link l = { .state = -1 };

    if (nlh->nlmsg_type == RTM_DELLINK) {
	port_del(ifi->ifi_index);
	iface_del(ifi->ifi_index, ifi->ifi_flags);
	return;
    }

    if (ifi->ifi_family == AF_BRIDGE) {
	link_attrs(nlh, &l);
	if (l.master && l.state >= 0)
	    port_state(ifi->ifi_index, l.master, l.state);
	return;
    }

    if (!config_find_ifindex(ifi->ifi_index))
	iface_add(ifi->ifi_index, ifi->ifi_flags);
    else
	iface_check(ifi->ifi_index, ifi->ifi_flags);
}

static void netlink_read(int sd, void *arg)
{
    char buffer[4096];
    ssize_t len;

    while ((len = recv(sd, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) {
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

        while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
            if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
                struct rtattr *rth = IFA_RTA(ifa);
                int rtl = IFA_PAYLOAD(nlh);

                for (; rtl && RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
		    struct sockaddr_storage ss = { 0 };
		    struct sockaddr *sa = (struct sockaddr *)&ss;
		    int flags = IFF_UP | IFF_MULTICAST;

		    /* IPv4 has the local address in IFA_LOCAL, IPv6 in IFA_ADDRESS */
		    if (ifa->ifa_family == AF_INET && rth->rta_type == IFA_LOCAL) {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			sin->sin_family = AF_INET;
			sin->sin_addr = *(struct in_addr *)RTA_DATA(rth);
		    } else if (ifa->ifa_family == AF_INET6 && rth->rta_type == IFA_ADDRESS) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = *(struct in6_addr *)RTA_DATA(rth);
		    } else
			continue;

		    if (nlh->nlmsg_type == RTM_NEWADDR)
			config_iface_addr_add(ifa->ifa_index, sa, flags);
		    else
			config_iface_addr_del(ifa->ifa_index, sa);
                }
            }

            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
		link_msg(nlh);

	    nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

/*
 * One RTM_GETLINK request on a socket of its own, cb for each reply.
 * A dump (NLM_F_DUMP) runs to NLMSG_DONE, a lookup is one message.
 */
static int link_request(int family, int ifindex, int flags, void (*cb)(struct nlmsghdr *, void *), void *arg)
{
    struct {
	struct nlmsghdr nlh;
	struct ifinfomsg ifi;
    } req = { 0 };
    char buf[16384];
    int done = 0;
    int rsd;

    rsd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rsd == -1)
	return -1;

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.ifi));
    req.nlh.nlmsg_type  = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | flags;
    req.ifi.ifi_family  = family;
    req.ifi.ifi_index   = ifindex;

    if (send(rsd, &req, req.nlh.nlmsg_len, 0) == -1) {
	close(rsd);
	return -1;
    }

    while (!done) {
	ssize_t len = recv(rsd, buf, sizeof(buf), 0);
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	if (len <= 0)
	    break;

	for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
	    if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
		done = 1;
		break;
	    }

	    cb(nlh, arg);
	    if (!(flags & NLM_F_DUMP))
		done = 1;
	}
    }

    close(rsd);
    return 0;
}

static void lower_cb(struct nlmsghdr *nlh, void *arg)
{
    struct link l = { 0 };

    link_attrs(nlh, &l);
    *(int *)arg = l.lower;
}

/* The interface below a vlan interface, or 0 */
int netlink_link_lower(int ifindex)
{
    int lower = 0;

    link_request(AF_UNSPEC, ifindex, 0, lower_cb, &lower);

    return lower;
}

static void port_cb(struct nlmsghdr *nlh, void *arg)
{
    link_msg(nlh);
}

void netlink_init(void)
{
    struct sockaddr_nl addr = { 0 };

    sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sd == -1) {
	err("failed opening NETLINK socket");
	exit(EX_OSERR);
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_LINK;
    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	err("failed binding NETLINK socket");
	close(sd);
	exit(EX_OSERR);
    }

    id = pev_sock_add(sd, netlink_read, NULL);
    if (id == -1) {
	err("failed registering NETLINK handler");
	exit(EX_OSERR);
    }

    /*
     * Current state of all bridge ports, so only a change is one.
     * Runs before iface_init(), no interface is querier yet, so
     * this sends nothing.
     */
    link_request(AF_BRIDGE, 0, NLM_F_DUMP, port_cb, NULL);
}

void netlink_exit(void)
{
    struct port *p, *tmp;

    TAILQ_FOREACH_SAFE(p, &ports, link, tmp) {
	TAILQ_REMOVE(&ports, p, link);
	free(p);
    }

    pev_sock_del(id);
    close(sd);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
