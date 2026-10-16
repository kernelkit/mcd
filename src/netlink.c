/* SPDX-License-Identifier: ISC */

#include <string.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "defs.h"

static int id;
static int sd;


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

            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
                struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);

		if (nlh->nlmsg_type == RTM_NEWLINK) {
		    if (!config_find_ifindex(ifi->ifi_index))
			iface_add(ifi->ifi_index, ifi->ifi_flags);
		    else
			iface_check(ifi->ifi_index, ifi->ifi_flags);
		} else
		    iface_del(ifi->ifi_index, ifi->ifi_flags);
	    }

	    nlh = NLMSG_NEXT(nlh, len);
        }
    }
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
}

void netlink_exit(void)
{
    pev_sock_del(id);
    close(sd);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
