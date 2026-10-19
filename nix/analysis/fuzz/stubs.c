/*
 * Stand-ins for main.c, pev.c and sock.c, linked into every fuzz harness.
 * See fuzz_harness.h for the contract.
 *
 * SPDX-License-Identifier: ISC
 */

#include "defs.h"
#include "pev.h"
#include "sock.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "fuzz_harness.h"

/* ── main.c globals ─────────────────────────────────────────────── */
int haveterminal = 0;
int running = 1;
int use_syslog = 0;
time_t mcd_init_time;

char *config_file = "fuzz.conf";
char *pid_file    = NULL;
char *sock_file   = NULL;

char *ident       = PACKAGE_NAME;
char *prognm      = PACKAGE_NAME;
const char *versionstring = "mcd version " PACKAGE_VERSION;

void restart(void)
{
}

/* ── exit() / popen() wrappers (-Wl,--wrap=exit,--wrap=popen,...) ── */
jmp_buf fuzz_exit_jmp;
volatile int fuzz_exit_armed;

void __real_exit(int status) __attribute__((noreturn));
void __wrap_exit(int status) __attribute__((noreturn));

void __wrap_exit(int status)
{
	if (fuzz_exit_armed) {
		fuzz_exit_armed = 0;
		longjmp(fuzz_exit_jmp, 1);
	}
	__real_exit(status);
}

static uint8_t *popen_data;
static size_t popen_len;

void fuzz_popen_set(const uint8_t *data, size_t len)
{
	free(popen_data);
	popen_data = NULL;
	popen_len = 0;
	if (!len)
		return;

	popen_data = malloc(len);
	if (!popen_data)
		abort();
	memcpy(popen_data, data, len);
	popen_len = len;
}

FILE *__wrap_popen(const char *cmd, const char *mode);
int __wrap_pclose(FILE *fp);

/* Every command "prints" the configured data; nothing is executed. */
FILE *__wrap_popen(const char *cmd, const char *mode)
{
	(void)cmd;
	(void)mode;

	if (!popen_len)
		return fopen("/dev/null", "r");

	return fmemopen(popen_data, popen_len, "r");
}

int __wrap_pclose(FILE *fp)
{
	return fclose(fp);
}

/* ── sock.c ─────────────────────────────────────────────────────── */
uint8_t *recv_buf;
uint8_t *send_buf;
size_t fuzz_sent_packets;

void sock_init(void)
{
}

void sock_exit(void)
{
}

void sock_iface_init(struct ifi *ifi)
{
	(void)ifi;
}

void sock_iface_exit(struct ifi *ifi)
{
	(void)ifi;
}

void sock_reload_begin(void)
{
}

void sock_reload_end(void)
{
}

/* Same frame layout as sock.c's build_ether(), including the 802.1Q tag
 * of raw VLAN mode. */
size_t build_ether(uint8_t *buf, const struct ifi *ifi, const uint8_t *dmac, uint16_t proto)
{
	struct ether_header *eh = (struct ether_header *)buf;
	size_t len = sizeof(*eh);

	memcpy(eh->ether_dhost, dmac, sizeof(eh->ether_dhost));
	memcpy(eh->ether_shost, ifi->ifi_hwaddr, sizeof(eh->ether_shost));

	if (ifi->ifi_vlan) {
		uint16_t tag[2];

		eh->ether_type = htons(ETH_P_8021Q);
		tag[0] = htons((6 << 13) | ifi->ifi_vlan);
		tag[1] = htons(proto);
		memcpy(buf + len, tag, sizeof(tag));
		len += sizeof(tag);
	} else
		eh->ether_type = htons(proto);

	return len;
}

int sock_send(const struct ifi *ifi, size_t len)
{
	(void)ifi;

	/* send_buf ends exactly RECV_BUF_SIZE on, so ASan has already
	 * caught any overflow while building; this catches a bad length. */
	if (len > RECV_BUF_SIZE)
		abort();
	fuzz_sent_packets++;

	return 0;
}

int mcast_join(const struct ifi *ifi, const inet_addr_t *group)
{
	(void)ifi;
	(void)group;

	return 0;
}

/* ── pev.c ──────────────────────────────────────────────────────── */
/*
 * Timers keep pev.c's observable semantics: ids are never reused, a
 * one-shot timer stays deletable after it fires, deleting runs the
 * cb_del registered for it. Nothing is scheduled; fuzz_timers_fire()
 * runs every live timer once.
 */
#define MAX_TIMERS 8192

struct ftimer {
	int id;
	int live;		/* not deleted */
	int armed;		/* will fire */
	int timeout, period;
	void (*cb)(int, void *);
	void (*cb_del)(void *);
	void *arg;
};

static struct ftimer timers[MAX_TIMERS];
static int next_id = 1;

static struct ftimer *timer_find(int id)
{
	for (int i = 0; i < MAX_TIMERS; i++) {
		if (timers[i].live && timers[i].id == id)
			return &timers[i];
	}
	errno = ENOENT;
	return NULL;
}

int pev_init(void)
{
	return 0;
}

int pev_exit(int status)
{
	return status;
}

int pev_run(void)
{
	return 0;
}

int pev_sig_add(int signo, void (*cb)(int, void *), void *arg)
{
	(void)signo;
	(void)cb;
	(void)arg;
	return next_id++;
}

int pev_sig_del(int id)
{
	(void)id;
	return 0;
}

int pev_sig_set_cb_del(int id, void (*cb)(void *))
{
	(void)id;
	(void)cb;
	return 0;
}

int pev_sock_add(int sd, void (*cb)(int, void *), void *arg)
{
	(void)sd;
	(void)cb;
	(void)arg;
	return next_id++;
}

int pev_sock_del(int id)
{
	(void)id;
	return 0;
}

int pev_sock_open(int domain, int type, int proto, void (*cb)(int, void *), void *arg)
{
	(void)cb;
	(void)arg;
	return socket(domain, type, proto);
}

int pev_sock_close(int sd)
{
	return close(sd);
}

int pev_sock_set_cb_del(int id, void (*cb)(void *))
{
	(void)id;
	(void)cb;
	return 0;
}

int pev_timer_add(int timeout, int period, void (*cb)(int, void *), void *arg)
{
	if ((timeout <= 0 && period <= 0) || !cb) {
		errno = EINVAL;
		return -1;
	}

	for (int i = 0; i < MAX_TIMERS; i++) {
		struct ftimer *t = &timers[i];

		if (t->live)
			continue;

		*t = (struct ftimer){
			.id = next_id++, .live = 1, .armed = 1,
			.timeout = timeout, .period = period,
			.cb = cb, .arg = arg,
		};
		return t->id;
	}

	errno = ENOMEM;
	return -1;
}

int pev_timer_del(int id)
{
	struct ftimer *t = timer_find(id);

	if (!t)
		return -1;

	t->live = t->armed = 0;
	if (t->cb_del)
		t->cb_del(t->arg);

	return 0;
}

int pev_timer_set(int id, int timeout)
{
	struct ftimer *t = timer_find(id);

	if (!t)
		return -1;

	t->timeout = timeout;
	t->armed = 1;

	return 0;
}

int pev_timer_get(int id)
{
	struct ftimer *t = timer_find(id);

	if (!t)
		return -1;

	return t->timeout ? t->timeout : t->period;
}

int pev_timer_set_cb_del(int id, void (*cb)(void *))
{
	struct ftimer *t = timer_find(id);

	if (!t)
		return -1;

	t->cb_del = cb;

	return 0;
}

void fuzz_timers_fire(void)
{
	int last = next_id;

	/* Only timers that existed on entry; callbacks may add/delete. */
	for (int i = 0; i < MAX_TIMERS; i++) {
		struct ftimer *t = &timers[i];
		int timeout;

		if (!t->live || !t->armed || t->id >= last)
			continue;

		timeout = t->timeout ? t->timeout : t->period;
		t->timeout = 0;
		t->cb(timeout, t->arg);

		/* The callback may have deleted or re-armed the slot. */
		if (t->live && !t->period && !t->timeout)
			t->armed = 0;
	}
}

void fuzz_timers_clear(void)
{
	for (int i = 0; i < MAX_TIMERS; i++) {
		if (timers[i].live)
			pev_timer_del(timers[i].id);
	}
}

/* ── globals and interfaces ─────────────────────────────────────── */
static struct {
	int router_alert;
	uint32_t router_timeout, qi, qri, lmi, robustness;
} saved;

void fuzz_init(void)
{
	/*
	 * logging == 0 prints everything to stderr, unfiltered (prinl()).
	 * logging == 1 goes through logger(), which formats every message,
	 * so the format strings are still exercised, and then syslog(), which
	 * the mask reduces to a no-op: mcd never logs LOG_EMERG.
	 */
	if (getenv("FUZZ_VERBOSE")) {
		logging = 0;
	} else {
		logging = 1;
		loglevel = LOG_DEBUG;
		setlogmask(LOG_UPTO(LOG_EMERG));
	}

	/* Laid out as sock_init() does, aligned IP headers included */
	recv_buf = calloc(1, SOCK_BUF_ALIGN + RECV_BUF_SIZE);
	send_buf = calloc(1, SOCK_BUF_ALIGN + RECV_BUF_SIZE);
	if (!recv_buf || !send_buf)
		abort();
	recv_buf += SOCK_BUF_ALIGN;
	send_buf += SOCK_BUF_ALIGN;

	igmp_init();

	saved.router_alert = router_alert;
	saved.router_timeout = router_timeout;
	saved.qi = igmp_query_interval;
	saved.qri = igmp_response_interval;
	saved.lmi = igmp_last_member_interval;
	saved.robustness = igmp_robustness;
}

void fuzz_reset_globals(void)
{
	router_alert = saved.router_alert;
	router_timeout = saved.router_timeout;
	igmp_query_interval = saved.qi;
	igmp_response_interval = saved.qri;
	igmp_last_member_interval = saved.lmi;
	igmp_robustness = saved.robustness;
}

#define FUZZ_IFINDEX 4242	/* no such interface in the sandbox */

struct ifi *fuzz_iface_up(unsigned int mode, int family)
{
	static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x01 };
	struct sockaddr_in sin = { .sin_family = AF_INET };
	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };
	struct ifi *ifi, *twin, *e;
	int compat;

	compat = mode & FUZZ_MODE_COMPAT_MASK;
	if (!compat)
		compat = GEN_V3;

	ifi = config_iface_add("fuzz0");
	twin = config_iface_twin(ifi);

	for (e = ifi; e; e = (e == ifi ? twin : NULL)) {
		e->ifi_index = FUZZ_IFINDEX;
		e->ifi_compat = (e->ifi_family == AF_INET6 && compat == GEN_V1) ? GEN_V2 : compat;
		memcpy(e->ifi_hwaddr, mac, sizeof(mac));
		e->ifi_flags &= ~IFIF_DISABLED;
		if (mode & FUZZ_MODE_DISABLED)
			e->ifi_flags |= IFIF_DISABLED;
		if (mode & FUZZ_MODE_PROXY)
			e->ifi_flags |= IFIF_PROXY_QUERIER;
		if (mode & FUZZ_MODE_VLAN)
			e->ifi_vlan = 10;
	}

	/* 10.0.0.10 / fe80::10 win elections against the seeds' 10.0.0.20 /
	 * fe80::20; .200 / ::200 lose them. */
	sin.sin_addr.s_addr = htonl((mode & FUZZ_MODE_HIGH_ADDR) ? 0x0a0000c8 : 0x0a00000a);
	inet_pton(AF_INET6, (mode & FUZZ_MODE_HIGH_ADDR) ? "fe80::200" : "fe80::10", &sin6.sin6_addr);
	config_iface_addr_add(FUZZ_IFINDEX, (struct sockaddr *)&sin, IFF_UP | IFF_MULTICAST);
	config_iface_addr_add(FUZZ_IFINDEX, (struct sockaddr *)&sin6, IFF_UP | IFF_MULTICAST);

	iface_check(FUZZ_IFINDEX, IFF_UP | IFF_MULTICAST);

	return family == AF_INET6 && twin ? twin : ifi;
}

void fuzz_iface_down(void)
{
	iface_exit();
	fuzz_timers_clear();
	fuzz_reset_globals();
	fuzz_sent_packets = 0;
}
