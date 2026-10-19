/*
 * Unit test of the pev.c timer arithmetic: a timer's expiry must be a
 * normalized timespec (0 <= tv_nsec < 1000000000), and the itimer armed
 * from it a valid one (0 <= tv_usec < 1000000), whatever the clock reads.
 *
 * pev.c is included to reach its static timer_run(); clock_gettime() and
 * setitimer() are wrapped (-Wl,--wrap=...) to feed a chosen clock and
 * check the armed value instead of arming it.
 *
 * SPDX-License-Identifier: ISC
 */

#include "pev.c"

/*
 * Not static: the compiler sees setitimer(), not its wrapper, and would
 * assume the call cannot change file-local state.
 */
struct timespec fake_now;
struct itimerval armed;
int armed_ok;

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts);
int __wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
	(void)clk;
	*ts = fake_now;
	return 0;
}

int __wrap_setitimer(int which, const struct itimerval *it, struct itimerval *old);
int __wrap_setitimer(int which, const struct itimerval *it, struct itimerval *old)
{
	(void)which;
	(void)old;
	armed = *it;
	armed_ok = it->it_value.tv_usec >= 0 && it->it_value.tv_usec < 1000000;
	if (!armed_ok) {
		errno = EINVAL;	/* what the kernel says */
		return -1;
	}
	return 0;
}

static void cb(int timeout, void *arg)
{
	(void)timeout;
	(void)arg;
}

static const struct {
	const char *description;
	struct timespec now;
	int timeout;			/* usec */
	struct timespec expected;	/* expiry */
} tests[] = {
	{ "whole second from a whole second",
	  { 100, 0 }, 1000000, { 101, 0 } },
	{ "within the second",
	  { 100, 0 }, 999999, { 100, 999999000 } },
	{ "just short of the next second",
	  { 100, 499999999 }, 500000, { 100, 999999999 } },
	{ "exactly on the next second",
	  { 100, 500000000 }, 500000, { 101, 0 } },
	{ "exactly on a later second, multi-second timeout",
	  { 100, 250000000 }, 2750000, { 103, 0 } },
	{ "carries past the next second",
	  { 100, 999999999 }, 1, { 101, 999 } },
	{ "carries past a later second, multi-second timeout",
	  { 100, 999000000 }, 1500000, { 102, 499000000 } },
};

int main(void)
{
	int fail = 0;

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		struct pev *entry;
		int id;

		fake_now = tests[i].now;
		armed_ok = 0;

		id = pev_timer_add(tests[i].timeout, 0, cb, NULL);
		timer_run(0, NULL);

		for (entry = pl; entry; entry = entry->next)
			if (entry->id == id)
				break;

		if (!entry) {
			printf("FAIL: %s: timer %d not found\n", tests[i].description, id);
			fail = 1;
		} else if (entry->expiry.tv_sec != tests[i].expected.tv_sec ||
			   entry->expiry.tv_nsec != tests[i].expected.tv_nsec) {
			printf("FAIL: %s: expiry %lld.%09ld, expected %lld.%09ld\n",
			       tests[i].description,
			       (long long)entry->expiry.tv_sec, entry->expiry.tv_nsec,
			       (long long)tests[i].expected.tv_sec, tests[i].expected.tv_nsec);
			fail = 1;
		} else if (!armed_ok) {
			printf("FAIL: %s: armed an invalid itimer %lld.%06ld\n",
			       tests[i].description,
			       (long long)armed.it_value.tv_sec, (long)armed.it_value.tv_usec);
			fail = 1;
		} else
			printf("ok:   %s\n", tests[i].description);

		/* Retire the timer before the next row */
		if (entry)
			entry->active = 0;
		pev_cleanup();
	}

	/*
	 * The consequence: an expiry left at tv_nsec 1000000000 arms an
	 * invalid itimer once the clock reads the next whole second, and
	 * timer_start() ignores the EINVAL, so no timer fires again.
	 */
	{
		const struct timespec now = { 100, 500000000 }, later = { 101, 0 };
		int id;

		fake_now = now;
		id = pev_timer_add(500000, 0, cb, NULL);
		timer_run(0, NULL);

		fake_now = later;
		armed_ok = 0;
		timer_start(&fake_now);
		if (!armed_ok) {
			printf("FAIL: timer %d due at the next second: armed an invalid itimer %lld.%06ld\n",
			       id, (long long)armed.it_value.tv_sec, (long)armed.it_value.tv_usec);
			fail = 1;
		} else
			printf("ok:   timer due at the next second arms a valid itimer\n");
	}

	return fail;
}
