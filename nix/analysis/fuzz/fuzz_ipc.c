/*
 * libFuzzer harness for the IPC server: ipc_handle() in src/ipc.c, which
 * accepts a client on the UNIX socket, reads one command, matches it
 * against the command table, parses the options and runs the handler
 * (help, version, show igmp / groups / mdb / router ports / status ...).
 *
 * ipc.c is included rather than linked to reach the static ipc_handle().
 * Each input is written by a fresh client to a listening socket in the
 * abstract namespace, against an interface that has seen one IGMPv2
 * report, so the show handlers have state to print. Commands that would
 * run `bridge`/`ip`/`jq` get empty output from the popen() wrapper.
 *
 * SPDX-License-Identifier: ISC
 */

#include "ipc.c"

#include <sys/socket.h>
#include <sys/un.h>

#include "fuzz_harness.h"

static int listen_sd = -1;
static struct sockaddr_un addr;
static socklen_t addrlen;

/* IGMPv2 report for 239.1.2.3 from 10.0.0.20 (IP header + IGMP). */
static const uint8_t report[] = {
	0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x01, 0x02, 0, 0,
	10, 0, 0, 20, 239, 1, 2, 3,
	0x16, 0x00, 0x00, 0x00, 239, 1, 2, 3,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	fuzz_init();

	listen_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sd < 0)
		abort();
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: nothing on the file system, unique per pid. */
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "mcd-fuzz-ipc-%d", getpid());
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);
	if (bind(listen_sd, (struct sockaddr *)&addr, addrlen) || listen(listen_sd, 1))
		abort();

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t pkt[sizeof(report)];
	char drain[4096];
	struct ifi *ifi;
	int client;

	/* ipc_read() takes at most sizeof(cmd) - 1 = 767 bytes in one read. */
	if (size > 767)
		size = 767;

	ifi = fuzz_iface_up(0, AF_INET);
	memcpy(pkt, report, sizeof(pkt));
	accept_igmp(ifi, 0, pkt, sizeof(pkt));

	client = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client < 0 || connect(client, (struct sockaddr *)&addr, addrlen))
		abort();
	if (size && write(client, data, size) != (ssize_t)size)
		abort();
	shutdown(client, SHUT_WR);

	if (setjmp(fuzz_exit_jmp) == 0) {
		fuzz_exit_armed = 1;
		ipc_handle(listen_sd, NULL);
	}
	fuzz_exit_armed = 0;

	while (read(client, drain, sizeof(drain)) > 0)
		;
	close(client);

	fuzz_iface_down();

	return 0;
}
