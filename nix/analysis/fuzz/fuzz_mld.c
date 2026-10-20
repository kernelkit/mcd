/*
 * libFuzzer harness for MLD receive: accept_mld() (src/mld.c), including
 * its hop-by-hop extension header walk, and the shared querier state
 * machine in src/iface.c (MLDv1/v2 queries, reports, done messages).
 *
 * Input: see packet.h. accept_mld() drops packets with a bad ICMPv6
 * checksum, so unless FUZZ_MODE_RAW_CKSUM is set the harness first
 * recomputes it; the fuzzer then reaches the parsers behind the check
 * instead of spending its time on the checksum.
 *
 * SPDX-License-Identifier: ISC
 */

#include "defs.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "fuzz_harness.h"
#include "packet.h"

#define FUZZ_MODE_RAW_CKSUM 0x40	/* leave the checksum as given */

/* RFC 4443 checksum: pseudo-header (src, dst, length, next header) plus
 * the ICMPv6 message. */
static uint16_t cksum6(const struct ip6_hdr *ip6, const uint8_t *msg, size_t len)
{
	uint32_t sum = 0;
	const uint8_t *p;
	size_t i;

	p = (const uint8_t *)&ip6->ip6_src;
	for (i = 0; i < 32; i += 2)
		sum += (uint32_t)p[i] << 8 | p[i + 1];
	sum += (uint32_t)(len >> 16) + (uint32_t)(len & 0xffff);
	sum += IPPROTO_ICMPV6;

	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)msg[i] << 8 | msg[i + 1];
	if (len & 1)
		sum += (uint32_t)msg[len - 1] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

/* Mirror accept_mld()'s header walk to find the ICMPv6 message; leave the
 * packet alone wherever accept_mld() would reject it anyway. */
static void fix_cksum(uint8_t *buf, size_t len)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct icmp6_hdr *icmp;
	size_t off = sizeof(*ip6), plen;
	uint8_t nxt;
	uint16_t c;

	if (len < sizeof(*ip6))
		return;
	plen = ntohs(ip6->ip6_plen);
	if (sizeof(*ip6) + plen > len)
		return;

	nxt = ip6->ip6_nxt;
	if (nxt == IPPROTO_HOPOPTS) {
		struct ip6_hbh *hbh = (struct ip6_hbh *)(buf + off);
		size_t hlen;

		if (plen < sizeof(*hbh))
			return;
		hlen = (size_t)(hbh->ip6h_len + 1) * 8;
		if (hlen > plen)
			return;
		nxt = hbh->ip6h_nxt;
		off += hlen;
		plen -= hlen;
	}
	if (nxt != IPPROTO_ICMPV6 || plen < sizeof(*icmp))
		return;

	icmp = (struct icmp6_hdr *)(buf + off);
	icmp->icmp6_cksum = 0;
	c = cksum6(ip6, buf + off, plen);
	icmp->icmp6_cksum = htons(c);
}

static void one(uint8_t *pkt, size_t len, unsigned int mode, void *ctx)
{
	struct ifi *ifi = ctx;

	if (!(mode & FUZZ_MODE_RAW_CKSUM))
		fix_cksum(pkt, len);

	accept_mld(ifi, ifi->ifi_vlan, pkt, len);
	if (mode & FUZZ_MODE_TIMERS)
		fuzz_timers_fire();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ifi *ifi;

	if (size < 1)
		return 0;

	ifi = fuzz_iface_up(data[0], AF_INET6);
	fuzz_packets(data, size, one, ifi);
	fuzz_iface_down();

	return 0;
}
