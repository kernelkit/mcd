/*
 * libFuzzer harness for src/bridge.c's parsing of external command output:
 * the `bridge mdb show` line tokenizer (populate()), the jsmn-based JSON
 * readers behind bridge_prop() / the router-port queries, and the
 * `ip neigh` / `bridge fdb` scrapers (dumpster()).
 *
 * bridge.c is included rather than linked to reach its static functions.
 * Nothing is executed: the popen() wrapper hands every command the fuzz
 * input as its output.
 *
 * Input: byte 0 picks the routine; the rest is the command output.
 *
 * SPDX-License-Identifier: ISC
 */

#include "bridge.c"

#include "fuzz_harness.h"

static FILE *out;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_init();
	out = fopen("/dev/null", "w");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char addr[64] = "10.0.0.20", mac[32], port[32];

	if (size < 1)
		return 0;

	fuzz_popen_set(data + 1, size - 1);

	if (setjmp(fuzz_exit_jmp) == 0) {
		fuzz_exit_armed = 1;

		switch (data[0] % 6) {
		case 0:
			populate();
			break;
		case 1:
			show_bridge_groups(out);
			break;
		case 2:
			bridge_prop(out, "br0", "mcast_querier");
			break;
		case 3:
			bridge_router_ports(out, "br0");
			break;
		case 4:
			bridge_router_ports_all(out);
			break;
		case 5:
			dumpster(addr, mac, sizeof(mac), port, sizeof(port));
			break;
		}
	}
	fuzz_exit_armed = 0;

	drop();
	fuzz_popen_set(NULL, 0);

	return 0;
}
