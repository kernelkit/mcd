/* SPDX-License-Identifier: ISC */
/*
 * Send one Multicast Router Solicitation, RFC 4286, on an interface.
 * From https://github.com/troglobit/mrdisc, for the test suite.
 *
 *   solicit [-4|-6] IFNAME
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>

#define MC_ALL_ROUTERS		"224.0.0.2"
#define MC6_ALL_ROUTERS		"ff02::2"
#define IGMP_MRD_SOLICIT	0x31
#define ICMP6_MRD_SOLICIT	152

static uint16_t in_cksum(uint16_t *p, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i < len; i++)
		sum += ntohs(p[i]);

	sum = (sum % 0x10000) + (sum / 0x10000);

	return htons(((uint16_t)sum) ^ 0xffff);
}

static void bind_iface(int sd, const char *ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
		err(1, "Cannot bind socket to interface %s", ifname);
}

static int solicit4(const char *ifname)
{
	unsigned char ra[4] = { IPOPT_RA, 0x04, 0x00, 0x00 };
	struct sockaddr_in dest = { .sin_family = AF_INET };
	struct igmp igmp;
	int sd, ttl = 1;

	sd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	if (sd < 0)
		err(1, "Cannot open IPv4 socket");

	bind_iface(sd, ifname);
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
		err(1, "Cannot set TTL");
	if (setsockopt(sd, IPPROTO_IP, IP_OPTIONS, &ra, sizeof(ra)) < 0)
		err(1, "Cannot set Router Alert option");

	memset(&igmp, 0, sizeof(igmp));
	igmp.igmp_type = IGMP_MRD_SOLICIT;
	igmp.igmp_cksum = in_cksum((uint16_t *)&igmp, sizeof(igmp) / 2);

	dest.sin_addr.s_addr = inet_addr(MC_ALL_ROUTERS);
	if (sendto(sd, &igmp, 4, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		err(1, "Cannot send IGMP solicitation");

	return close(sd);
}

static int solicit6(const char *ifname)
{
	/* Hop-by-hop header: next, len, Router Alert type 5 len 2 value 0, PadN */
	unsigned char hopopt[8] = { 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 };
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6 };
	struct icmp6_hdr icmp6;
	int sd, hops = 1;

	sd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sd < 0)
		err(1, "Cannot open IPv6 socket");

	bind_iface(sd, ifname);
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0)
		err(1, "Cannot set hop limit");
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_HOPOPTS, &hopopt, sizeof(hopopt)) < 0)
		err(1, "Cannot set Router Alert option");

	memset(&icmp6, 0, sizeof(icmp6));
	icmp6.icmp6_type = ICMP6_MRD_SOLICIT;	/* checksum by the kernel */

	inet_pton(AF_INET6, MC6_ALL_ROUTERS, &dest.sin6_addr);
	if (sendto(sd, &icmp6, 4, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		err(1, "Cannot send ICMPv6 solicitation");

	return close(sd);
}

int main(int argc, char *argv[])
{
	int v4 = 1, v6 = 1;
	const char *ifname;
	int rc = 0;

	if (argc == 3 && !strcmp(argv[1], "-4"))
		v6 = 0;
	else if (argc == 3 && !strcmp(argv[1], "-6"))
		v4 = 0;
	else if (argc != 2)
		errx(1, "Usage: solicit [-4|-6] IFNAME");
	ifname = argv[argc - 1];

	if (v4)
		rc |= solicit4(ifname);
	if (v6)
		rc |= solicit6(ifname);

	return rc;
}
