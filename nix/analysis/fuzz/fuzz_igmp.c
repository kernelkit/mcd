/*
 * libFuzzer harness for IGMP receive: accept_igmp() (src/igmp.c) and the
 * querier state machine behind it in src/iface.c (membership queries and
 * elections, v1/v2 reports, leaves, v3 reports and their group records).
 *
 * Input: see packet.h. Each input runs on a fresh "fuzz0" interface; with
 * FUZZ_MODE_TIMERS every pending timer fires after each packet, reaching
 * the group-timeout, last-member-query and version-fallback paths.
 *
 * SPDX-License-Identifier: ISC
 */

#include "defs.h"

#include "fuzz_harness.h"
#include "packet.h"

static void one(uint8_t *pkt, size_t len, unsigned int mode, void *ctx)
{
	struct ifi *ifi = ctx;

	accept_igmp(ifi, ifi->ifi_vlan, pkt, len);
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

	ifi = fuzz_iface_up(data[0], AF_INET);
	fuzz_packets(data, size, one, ifi);
	fuzz_iface_down();

	return 0;
}
