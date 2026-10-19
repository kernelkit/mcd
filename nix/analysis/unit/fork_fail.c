/*
 * LD_PRELOAD shim: fork() fails, with the errno in $FORK_ERRNO (default
 * EAGAIN), and geteuid() says root, to get mcd past its root check in
 * the build sandbox.
 *
 * SPDX-License-Identifier: ISC
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

pid_t fork(void)
{
	const char *e = getenv("FORK_ERRNO");

	errno = e ? atoi(e) : EAGAIN;
	return -1;
}

uid_t geteuid(void)
{
	return 0;
}
