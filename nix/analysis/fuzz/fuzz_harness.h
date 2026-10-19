/*
 * Shared declarations for the mcd libFuzzer harnesses (nix/analysis/fuzz/).
 *
 * Each harness links the mcd objects it needs, except main.o, pev.o and
 * sock.o, which stubs.c replaces: timers go into a table the harness can
 * fire, packets "sent" are only counted, and exit() / popen() / pclose()
 * are wrapped at link time (-Wl,--wrap=...) so fatal() paths return to
 * the harness and external command output comes from the fuzz input.
 *
 * SPDX-License-Identifier: ISC
 */

#ifndef FUZZ_HARNESS_H
#define FUZZ_HARNESS_H

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

struct ifi;

/* libFuzzer entry points. Initialize is optional (replay_main.c checks). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

/*
 * exit() from mcd code longjmps here while armed, e.g.
 *
 *     if (setjmp(fuzz_exit_jmp) == 0) {
 *         fuzz_exit_armed = 1;
 *         config_init();
 *     }
 *     fuzz_exit_armed = 0;
 */
extern jmp_buf fuzz_exit_jmp;
extern volatile int fuzz_exit_armed;

/* One-time setup: quiet logging (FUZZ_VERBOSE=1 for debug), protocol
 * defaults, a snapshot of the tunable globals. */
void fuzz_init(void);

/* Restore the globals a config file or query may change. */
void fuzz_reset_globals(void);

/* Fire every pending timer once, as if all had expired. */
void fuzz_timers_fire(void);

/* Drop every timer, running its delete callback (frees callback args). */
void fuzz_timers_clear(void);

/* Data every popen() returns until changed (default: empty). */
void fuzz_popen_set(const uint8_t *data, size_t len);

/* Packets mcd built and handed to sock_send(). */
extern size_t fuzz_sent_packets;

/*
 * Bring up interface "fuzz0" (an AF_INET entry and its AF_INET6 twin)
 * with an address per family, as netlink would, then start it. `mode`
 * bits pick the configuration; see FUZZ_MODE_* below. Returns the entry
 * for `family`. fuzz_iface_down() tears everything down again.
 */
#define FUZZ_MODE_COMPAT_MASK	0x03	/* 1: v1, 2: v2, 0/3: v3 */
#define FUZZ_MODE_PROXY		0x04	/* proxy-mode (0.0.0.0 queries) */
#define FUZZ_MODE_DISABLED	0x08	/* querier disabled */
#define FUZZ_MODE_TIMERS	0x10	/* fire timers after each packet */
#define FUZZ_MODE_VLAN		0x20	/* raw VLAN mode, vid 10 */
#define FUZZ_MODE_HIGH_ADDR	0x80	/* our address loses elections */

struct ifi *fuzz_iface_up(unsigned int mode, int family);
void fuzz_iface_down(void);

#endif /* FUZZ_HARNESS_H */
