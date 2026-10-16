/* SPDX-License-Identifier: ISC */

#include <netdb.h>

#include "defs.h"
#include "inet.h"

/*
 * Exported variables.
 */
char s1[INET_ADDRSTR_LEN];		/* buffers to hold the string representations  */
char s2[INET_ADDRSTR_LEN];		/* of IP addresses, to be passed to inet_fmt() */
char s3[INET_ADDRSTR_LEN];		/* or inet_fmts().                             */
char s4[INET_ADDRSTR_LEN];

/*
 * Orders addresses numerically within a family, by family otherwise.
 * Unset addresses (AF_UNSPEC) compare equal to each other.
 */
int inet_addr_cmp(const inet_addr_t *a, const inet_addr_t *b)
{
    if (a->ss_family != b->ss_family)
	return a->ss_family < b->ss_family ? -1 : 1;

    switch (a->ss_family) {
    case AF_INET: {
	uint32_t ia = ntohl(inet_addr_get4(a));
	uint32_t ib = ntohl(inet_addr_get4(b));

	return ia < ib ? -1 : ia > ib;
    }

#ifdef AF_INET6
    case AF_INET6:
	return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
		      &((const struct sockaddr_in6 *)b)->sin6_addr, sizeof(struct in6_addr));
#endif

    default:
	return 0;
    }
}

int inet_addr_linklocal(const inet_addr_t *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
	return IN_LINKLOCAL(ntohl(inet_addr_get4(addr)));

#ifdef AF_INET6
    case AF_INET6:
	return IN6_IS_ADDR_LINKLOCAL(&((const struct sockaddr_in6 *)addr)->sin6_addr);
#endif

    default:
	return 0;
    }
}

/*
 * Copy only the part of sa that its family defines, the caller may
 * hand us a plain struct sockaddr_in.
 */
void inet_addr_set(inet_addr_t *addr, const struct sockaddr *sa)
{
    size_t len;

    switch (sa->sa_family) {
    case AF_INET:
	len = sizeof(struct sockaddr_in);
	break;

#ifdef AF_INET6
    case AF_INET6:
	len = sizeof(struct sockaddr_in6);
	break;
#endif

    default:
	len = sizeof(*sa);
	break;
    }

    memset(addr, 0, sizeof(*addr));
    memcpy(addr, sa, len);
}

/*
 * IPv4 address in network byte order, INADDR_ANY when unset or not IPv4
 */
uint32_t inet_addr_get4(const inet_addr_t *addr)
{
    if (addr->ss_family != AF_INET)
	return INADDR_ANY;

    return ((const struct sockaddr_in *)addr)->sin_addr.s_addr;
}

void inet_addr_set4(inet_addr_t *addr, uint32_t ina)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;

    memset(addr, 0, sizeof(*addr));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ina;
}

void inet_addr_set6(inet_addr_t *addr, const struct in6_addr *in6)
{
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

    memset(addr, 0, sizeof(*addr));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = *in6;
}

const struct in6_addr *inet_addr_get6(const inet_addr_t *addr)
{
    if (addr->ss_family != AF_INET6)
	return &in6addr_any;

    return &((const struct sockaddr_in6 *)addr)->sin6_addr;
}

/* Unset, 0.0.0.0 or :: */
int inet_addr_is_any(const inet_addr_t *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
	return inet_addr_get4(addr) == INADDR_ANY;
    case AF_INET6:
	return IN6_IS_ADDR_UNSPECIFIED(inet_addr_get6(addr));
    default:
	return 1;
    }
}

int inet_addr_is_group(const inet_addr_t *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
	return IN_MULTICAST(ntohl(inet_addr_get4(addr)));
    case AF_INET6:
	return IN6_IS_ADDR_MULTICAST(inet_addr_get6(addr));
    default:
	return 0;
    }
}

/* Groups in 224.0.0.0/24 and ff02::/16 are never tracked */
int inet_addr_is_lanscope(const inet_addr_t *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
	return ntohl(inet_addr_get4(addr)) <= INADDR_MAX_LOCAL_GROUP;
    case AF_INET6:
	return IN6_IS_ADDR_MC_LINKLOCAL(inet_addr_get6(addr)) ||
	       IN6_IS_ADDR_MC_NODELOCAL(inet_addr_get6(addr));
    default:
	return 0;
    }
}

char *inet_addr_fmt(const inet_addr_t *addr, char *s, size_t len)
{
    const void *src;

    switch (addr->ss_family) {
    case AF_INET:
	src = &((const struct sockaddr_in *)addr)->sin_addr;
	break;

#ifdef AF_INET6
    case AF_INET6:
	src = &((const struct sockaddr_in6 *)addr)->sin6_addr;
	break;
#endif

    default:			/* unset, IPv4 only until MLD lands */
	return inet_fmt(INADDR_ANY, s, len);
    }

    if (!inet_ntop(addr->ss_family, src, s, len))
	return inet_fmt(INADDR_ANY, s, len);

    return s;
}

/*
 * Verify that a given IP address is a valid multigast group
 */
int inet_valid_group(uint32_t naddr)
{
    uint32_t addr;

    addr = ntohl(naddr);

    return IN_MULTICAST(addr);
}

/*
 * Verify that a given IP address is credible as a host address.
 * (Without a mask, cannot detect addresses of the form {subnet,0} or
 * {subnet,-1}.)
 */
int inet_valid_host(uint32_t naddr)
{
    uint32_t addr;

    addr = ntohl(naddr);

    return (!(IN_MULTICAST(addr) ||
	      IN_BADCLASS (addr) ||
	      (addr & 0xff000000) == 0));
}

/*
 * Verify that a given netmask is plausible;
 * make sure that it is a series of 1's followed by
 * a series of 0's with no discontiguous 1's.
 */
int inet_valid_mask(uint32_t mask)
{
    if (~(((mask & -mask) - 1) | mask) != 0) {
	/* Mask is not contiguous */
	return 0;
    }

    return 1;
}

/*
 * Verify that a given subnet number and mask pair are credible.
 *
 * With CIDR, almost any subnet and mask are credible.  mrouted still
 * can't handle aggregated class A's, so we still check that, but
 * otherwise the only requirements are that the subnet address is
 * within the [ABC] range and that the host bits of the subnet
 * are all 0.
 */
int inet_valid_subnet(uint32_t nsubnet, uint32_t nmask)
{
    uint32_t subnet, mask;

    subnet = ntohl(nsubnet);
    mask   = ntohl(nmask);

    if ((subnet & mask) != subnet)
	return 0;

    if (subnet == 0)
	return mask == 0;

    if (IN_CLASSA(subnet)) {
	if (mask < 0xff000000 ||
	    (subnet & 0xff000000) == 0x7f000000 ||
	    (subnet & 0xff000000) == 0x00000000)
	    return 0;
    } else if (IN_CLASSD(subnet) || IN_BADCLASS(subnet)) {
	/* Above Class C address space */
	return 0;
    }

    if (subnet & ~mask) {
	/* Host bits are set in the subnet */
	return 0;
    }

    if (!inet_valid_mask(mask)) {
	/* Netmask is not contiguous */
	return 0;
    }

    return 1;
}


/*
 * Convert an IP address to name
 */
char *inet_name(uint32_t addr, int numeric)
{
    static char host[NI_MAXHOST];
    struct sockaddr_in sin;
    struct sockaddr *sa;
    struct in_addr in;
    int rc;

    if (addr == 0)
	return "local";

    if (numeric) {
	in.s_addr = addr;
	return inet_ntoa(in);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sa = (struct sockaddr *)&sin;

    rc = getnameinfo(sa, sizeof(sin), host, sizeof(host), NULL, 0, 0);
    if (rc)
	return NULL;

    return host;
}


/*
 * Convert an IP address in uint32_t (network) format into a printable string.
 */
char *inet_fmt(uint32_t addr, char *s, size_t len)
{
    uint8_t *a;

    a = (uint8_t *)&addr;
    snprintf(s, len, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

    return s;
}

/*
 * Convert an IP subnet number in uint32_t (network) format into a printable
 * string including the netmask as a number of bits.
 */
char *inet_fmts(uint32_t addr, uint32_t mask, char *s, size_t len)
{
    uint8_t *a, *m;
    int bits;

    if ((addr == 0) && (mask == 0)) {
	snprintf(s, len, "default");
	return s;
    }
    a = (uint8_t *)&addr;
    m = (uint8_t *)&mask;
    bits = 33 - ffs(ntohl(mask));

    if      (m[3] != 0) snprintf(s, len, "%u.%u.%u.%u/%d", a[0], a[1], a[2], a[3],
						bits);
    else if (m[2] != 0) snprintf(s, len, "%u.%u.%u/%d",    a[0], a[1], a[2], bits);
    else if (m[1] != 0) snprintf(s, len, "%u.%u/%d",       a[0], a[1], bits);
    else                snprintf(s, len, "%u/%d",          a[0], bits);

    return s;
}

/*
 * Convert the printable string representation of an IP address into the
 * uint32_t (network) format.  Return 0xffffffff on error.  (To detect the
 * legal address with that value, you must explicitly compare the string
 * with "255.255.255.255".)
 */
uint32_t inet_parse(char *s, int n)
{
    uint32_t a = 0;
    uint32_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
    int i;
    char c;

    i = sscanf(s, "%u.%u.%u.%u%c", &a0, &a1, &a2, &a3, &c);
    if (i < n || i > 4 || a0 > 255 || a1 > 255 || a2 > 255 || a3 > 255)
	return 0xffffffff;

    ((uint8_t *)&a)[0] = a0;
    ((uint8_t *)&a)[1] = a1;
    ((uint8_t *)&a)[2] = a2;
    ((uint8_t *)&a)[3] = a3;

    return a;
}


/*
 * inet_cksum extracted from:
 *			P I N G . C
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 * Modified at Uc Berkeley
 *
 * (ping.c) Status -
 *	Public Domain.  Distribution Unlimited.
 *
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
int inet_cksum(uint16_t *addr, uint32_t len)
{
    int nleft = (int)len;
    uint16_t *w = addr;
    uint16_t answer = 0;
    int32_t sum = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
	sum += *w++;
	nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
	*(uint8_t *) (&answer) = *(uint8_t *)w ;
	sum += answer;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;			/* truncate to 16 bits */

    return answer;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
