/* SPDX-License-Identifier: ISC */

#include <ifaddrs.h>

#include "defs.h"
#include "inet.h"

/*
 * Exported variables.
 */
struct ifaces ifaces = TAILQ_HEAD_INITIALIZER(ifaces);

void config_set_ifflag(uint32_t flag)
{
    struct ifi *ifi;

    TAILQ_FOREACH(ifi, &ifaces, ifi_link)
	ifi->ifi_flags |= flag;
}

struct ifi *config_iface_iter(int first)
{
    static struct ifi *next = NULL;
    struct ifi *ifi;

    if (first)
	ifi = TAILQ_FIRST(&ifaces);
    else
	ifi = next;

    if (ifi)
	next = TAILQ_NEXT(ifi, ifi_link);

    return ifi;
}

struct ifi *config_find_ifname(char *nm)
{
    struct ifi *ifi;

    if (!nm) {
	errno = EINVAL;
	return NULL;
    }

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
        if (!strcmp(ifi->ifi_name, nm))
            return ifi;
    }

    return NULL;
}

struct ifi *config_find_ifaddr(in_addr_t addr)
{
    struct ifi *ifi;

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	if (addr == ifi->ifi_inaddr)
            return ifi;
    }

    return NULL;
}

struct ifi *config_find_iface(int ifindex, int vid)
{
    struct ifi *ifi;

    TAILQ_FOREACH(ifi, &ifaces, ifi_link) {
	if (ifindex == ifi->ifi_index && vid == ifi->ifi_vlan)
            return ifi;
    }

    return NULL;
}

static int getmac(const char *ifname, uint8_t *mac, size_t size)
{
    struct ifreq ifr;
    int rc = 0;
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return 1;

    ifr.ifr_addr.sa_family = AF_INET;
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        rc = 1;
        goto done;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, size);

done:
    close(sock);

    return rc;
}

/*
 * Called by parser to add an interface to start or watch for in the future
 */
struct ifi *config_iface_add(char *ifname)
{
    struct ifi *ifi;
    int ifindex;

    ifi = config_find_ifname(ifname);
    if (ifi)
	return ifi;

    ifi = calloc(1, sizeof(struct ifi));
    if (!ifi) {
	err("failed allocating memory for iflist");
	exit(EX_OSERR);
    }

    iface_zero(ifi);
    strlcpy(ifi->ifi_name, ifname, sizeof(ifi->ifi_name));

    /*
     * May not exist yet, prepare for netlink event later
     */
    ifindex = if_nametoindex(ifname);
    if (ifindex)
	ifi->ifi_index = ifindex;
    else
	ifi->ifi_flags |= IFIF_DOWN;

    if (getmac(ifname, ifi->ifi_hwaddr, sizeof(ifi->ifi_hwaddr)))
	warn("failed finding hw address for iface %s", ifname);

    TAILQ_INSERT_TAIL(&ifaces, ifi, ifi_link);

    return ifi;
}

/*
 * Called by parser for 'vlan NUM', may create an interface clone of
 * the current interface with already learned settings.
 */
struct ifi *config_iface_vlan(struct ifi *ifi, int vid)
{
    struct ifi *clone;

    if (ifi->ifi_vlan == 0) {
	ifi->ifi_vlan = vid;
	return ifi;
    }

    clone = malloc(sizeof(*clone));
    if (!clone) {
	err("failed cloning %s for new VLAN %d", ifi->ifi_name, vid);
	exit(EX_OSERR);
    }

    memcpy(clone, ifi, sizeof(*clone));
    TAILQ_INSERT_TAIL(&ifaces, clone, ifi_link);

    clone->ifi_vlan = vid;

    return clone;
}

static struct ifi *addr_add(int ifindex, struct sockaddr *sa, unsigned int flags)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    struct phaddr *pa;
    struct ifi *ifi;

    /*
     * Ignore any interface for an address family other than IP
     */
    if (!sa || sa->sa_family != AF_INET)
	return NULL;

    /*
     * Ignore loopback interfaces and interfaces that do not support
     * multicast.
     */
    if ((flags & (IFF_LOOPBACK|IFF_MULTICAST)) != IFF_MULTICAST)
	return NULL;

    ifi = config_find_iface(ifindex, 0);
    if (!ifi)
	return NULL;

    /* kernel promotes secondary addresses, we know all addrs already */
    TAILQ_FOREACH(pa, &ifi->ifi_addrs, pa_link) {
	if (pa->pa_addr == sin->sin_addr.s_addr)
	    return NULL;	/* Already have it */
    }

    pa = calloc(1, sizeof(*pa));
    if (!pa) {
	err("failed allocating address for %s", ifi->ifi_name);
	exit(EX_OSERR);
    }

    pa->pa_addr  = sin->sin_addr.s_addr;
    TAILQ_INSERT_TAIL(&ifi->ifi_addrs, pa, pa_link);

    if (!(flags & IFF_UP))
	ifi->ifi_flags |= IFIF_DOWN;

    dbg("New address %s for %s flags 0x%x",
	  inet_fmt(pa->pa_addr, s1, sizeof(s1)), ifi->ifi_name, flags);

    return ifi;
}

static struct ifi *addr_del(int ifindex, struct sockaddr *sa)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    struct phaddr *pa, *tmp;
    struct ifi *ifi;

    /*
     * Ignore any interface for an address family other than IP
     */
    if (!sa || sa->sa_family != AF_INET)
	return NULL;

    ifi = config_find_iface(ifindex, 0);
    if (!ifi)
	return NULL;

    TAILQ_FOREACH_SAFE(pa, &ifi->ifi_addrs, pa_link, tmp) {
	if (pa->pa_addr != sin->sin_addr.s_addr)
	    continue;

	TAILQ_REMOVE(&ifi->ifi_addrs, pa, pa_link);
	dbg("Drop address %s for %s", inet_fmt(pa->pa_addr, s1, sizeof(s1)),
	      ifi->ifi_name);
	free(pa);
	return ifi;
    }

    return NULL;
}

void config_iface_addr_add(int ifindex, struct sockaddr *sa, unsigned int flags)
{
    struct ifi *ifi;

    ifi = addr_add(ifindex, sa, flags);
    if (ifi) {
	if (ifi->ifi_flags & IFIF_DISABLED) {
	    dbg("    %s disabled, no election", ifi->ifi_name);
	    return;
	}
	if (ifi->ifi_flags & IFIF_DOWN) {
	    dbg("    %s down, no election", ifi->ifi_name);
	    return;
	}

	iface_check_election(ifi);
    }
}

void config_iface_addr_del(int ifindex, struct sockaddr *sa)
{
    struct ifi *ifi;

    ifi = addr_del(ifindex, sa);
    if (ifi) {
	if (ifi->ifi_flags & IFIF_DISABLED) {
	    dbg("    %s disabled, no election", ifi->ifi_name);
	    return;
	}
	if (ifi->ifi_flags & IFIF_DOWN) {
	    dbg("    %s down, no election", ifi->ifi_name);
	    return;
	}

	iface_check_election(ifi);
    }
}

/*
 * Query the kernel to find network interfaces that are multicast-capable
 */
void config_iface_init(void)
{
    struct ifaddrs *ifa, *ifap;

    if (getifaddrs(&ifap) < 0) {
	err("getifaddrs");
	exit(EX_OSERR);
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	int ifindex;

	ifindex = if_nametoindex(ifa->ifa_name);
	if (!ifindex)
	    continue;

	addr_add(ifindex, ifa->ifa_addr, ifa->ifa_flags);
    }

    freeifaddrs(ifap);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
