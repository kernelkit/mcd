/*
 * Copyright (c) 2018-2020  Joachim Wiberg <troglobit@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IPC API:
 *    - text based for compat with similar daemons
 *    - required commands: HELP, SHOW, VERSION
 *
 * Client asks daemon for available commands with HELP (help sep. w/ two spaces)
 * Client can also send VERSION to get daemon version
 * Client can send SHOW to get general status overview
 *
 * Daemon requires commands to be EXACT MATCH, so the client must
 * translate any short-commands to the full command before sending
 * it to the daemon.
 *
 * Example:
 *           echo "help" |socat - UNIX-CONNECT:/run/querierd.sock
 */

#include <fcntl.h>
#include <stddef.h>
#include "defs.h"

#define ENABLED(v) (v ? "Enabled" : "Disabled")

static struct sockaddr_un sun;
static int ipc_sockid =  0;
static int ipc_socket = -1;
static int detail = 0;

enum {
	IPC_ERR = -1,
	IPC_OK  = 0,
	IPC_HELP,
	IPC_VERSION,
	IPC_IGMP,
	IPC_IGMP_GRP,
	IPC_IGMP_IFACE,
	IPC_STATUS
};

struct ipcmd {
	int   op;
	char *cmd;
	char *arg;
	char *help;
} cmds[] = {
	{ IPC_HELP,       "help", NULL, "This help text" },
	{ IPC_VERSION,    "version", NULL, "Show daemon version" },
//	{ IPC_IGMP_GRP,   "groups", NULL, "Show IGMP group memberships" },
//	{ IPC_IGMP_IFACE, "interfaces", NULL, "Show IGMP interface status" },
	{ IPC_STATUS,     "show status", NULL, "Show daemon status (default)" },
	{ IPC_IGMP,       "show igmp", NULL, "Show interfaces and group memberships" },
	{ IPC_STATUS,     "show", NULL, NULL }, /* hidden default */
};

static char *timetostr(time_t t, char *buf, size_t len)
{
	int sec, min, hour, day;
	static char tmp[20];

	if (!buf) {
		buf = tmp;
		len = sizeof(tmp);
	}

	day  = t / 86400;
	t    = t % 86400;
	hour = t / 3600;
	t    = t % 3600;
	min  = t / 60;
	t    = t % 60;
	sec  = t;

	if (day)
		snprintf(buf, len, "%dd%dh%dm%ds", day, hour, min, sec);
	else
		snprintf(buf, len, "%dh%dm%ds", hour, min, sec);

	return buf;
}

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1) {
		errno = EINVAL;
		return NULL;
	}

	p = str + strlen(str) - 1;
        while (*p == '\n')
		*p-- = 0;

	return str;
}

static void strip(char *cmd, size_t len)
{
	char *ptr;

	ptr = cmd + len;
	len = strspn(ptr, " \t\n");
	if (len > 0)
		ptr += len;

	memmove(cmd, ptr, strlen(ptr) + 1);
	chomp(cmd);
}

static void check_detail(char *cmd, size_t len)
{
	const char *det = "detail";
	char *ptr;

	strip(cmd, len);

	len = MIN(strlen(cmd), strlen(det));
	if (len > 0 && !strncasecmp(cmd, det, len)) {
		len = strcspn(cmd, " \t\n");
		strip(cmd, len);

		detail = 1;
	} else
		detail = 0;
}

static int ipc_read(int sd, char *cmd, ssize_t len)
{
	while ((len = read(sd, cmd, len - 1)) == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			continue;
		default:
			break;
		}
		return IPC_ERR;
	}
	if (len == 0)
		return IPC_OK;

	cmd[len] = 0;
//	logit(LOG_DEBUG, 0, "IPC cmd: '%s'", cmd);

	for (size_t i = 0; i < NELEMS(cmds); i++) {
		struct ipcmd *c = &cmds[i];
		size_t len = strlen(c->cmd);

		if (!strncasecmp(cmd, c->cmd, len)) {
			check_detail(cmd, len);
			return c->op;
		}
	}

	errno = EBADMSG;
	return IPC_ERR;
}

static int ipc_write(int sd, char *msg, size_t sz)
{
	ssize_t len;

//	logit(LOG_DEBUG, 0, "IPC rpl: '%s'", msg);

	while ((len = write(sd, msg, sz))) {
		if (-1 == len) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				continue;
			default:
				break;
			}
		}
		break;
	}

	if (len != (ssize_t)sz)
		return IPC_ERR;

	return 0;
}

static int ipc_close(int sd)
{
	return shutdown(sd, SHUT_RDWR) ||
		close(sd);
}

static int ipc_send(int sd, char *buf, size_t len, FILE *fp)
{
	while (fgets(buf, len, fp)) {
		if (!ipc_write(sd, buf, strlen(buf)))
			continue;

		logit(LOG_WARNING, errno, "Failed communicating with client");
		return IPC_ERR;
	}

	return ipc_close(sd);
}

static void ipc_show(int sd, int (*cb)(FILE *), char *buf, size_t len)
{
	FILE *fp;

	fp = tempfile();
	if (!fp) {
		logit(LOG_WARNING, errno, "Failed opening temporary file");
		return;
	}

	if (cb(fp))
		return;

	rewind(fp);
	ipc_send(sd, buf, len, fp);
	fclose(fp);
}

static int ipc_err(int sd, char *buf, size_t len)
{
	switch (errno) {
	case EBADMSG:
		snprintf(buf, len, "No such command, see 'help' for available commands.");
		break;

	case EINVAL:
		snprintf(buf, len, "Invalid argument.");
		break;

	default:
		snprintf(buf, len, "Unknown error: %s", strerror(errno));
		break;
	}

	return ipc_write(sd, buf, strlen(buf));
}

/* wrap simple functions that don't use >768 bytes for I/O */
static int ipc_wrap(int sd, int (*cb)(char *, size_t), char *buf, size_t len)
{
	if (cb(buf, len))
		return IPC_ERR;

	return ipc_write(sd, buf, strlen(buf));
}

static const char *ifstate(struct ifi *ifi)
{
	if (ifi->ifi_flags & IFIF_DOWN)
		return "Down";

	if (ifi->ifi_flags & IFIF_DISABLED)
		return "Disabled";

	return "Up";
}

#if 0
static int show_igmp_groups(FILE *fp)
{
	struct listaddr *group, *source;
	struct ifi *ifi;

	fprintf(fp, "IGMP Group Membership Table_\n");
	fprintf(fp, "Interface         Group            Source           Last Reported    Timeout=\n");
	for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
		for (group = ifi->ifi_groups; group; group = group->al_next) {
			char pre[40], post[40];

			snprintf(pre, sizeof(pre), "%-16s  %-15s  ",
				 ifi->ifi_name, inet_fmt(group->al_addr, s1, sizeof(s1)));

			snprintf(post, sizeof(post), "%-15s  %7u",
				 inet_fmt(group->al_reporter, s1, sizeof(s1)),
				 group->al_timer);

			if (!group->al_sources) {
				fprintf(fp, "%s%-15s  %s\n", pre, "ANY", post);
				continue;
			}

			for (source = group->al_sources; source; source = source->al_next)
				fprintf(fp, "%s%-15s  %s\n",
					pre, inet_fmt(source->al_addr, s1, sizeof(s1)), post);
		}
	}

	return 0;
}

static int show_igmp_iface(FILE *fp)
{
	struct listaddr *group;
	struct ifi *ifi;

	fprintf(fp, "IGMP Interface Table_\n");
	fprintf(fp, "Interface         State     Querier          Timeout Version  Groups=\n");

	struct ifi *ifi;
	for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
		size_t num = 0;
		char timeout[10];
		int version;

		if (!ifi->ifi_querier) {
			strlcpy(s1, "Local", sizeof(s1));
			snprintf(timeout, sizeof(timeout), "None");
		} else {
			inet_fmt(ifi->ifi_querier->al_addr, s1, sizeof(s1));
			snprintf(timeout, sizeof(timeout), "%u", igmp_querier_timeout - ifi->ifi_querier->al_timer);
		}

		for (group = ifi->ifi_groups; group; group = group->al_next)
			num++;

		if (ifi->ifi_flags & IFIF_IGMPV1)
			version = 1;
		else if (ifi->ifi_flags & IFIF_IGMPV2)
			version = 2;
		else
			version = 3;

		fprintf(fp, "%-16s  %-8s  %-15s  %7s %7d  %6zd\n", ifi->ifi_name,
			ifstate(ifi), s1, timeout, version, num);
	}

	return 0;
}

static int show_igmp(FILE *fp)
{
	int rc = 0;

	rc += show_igmp_iface(fp);
	rc += show_igmp_groups(fp);

	return rc;
}
#endif

static int show_igmp(FILE *fp)
{
	struct ifi *ifi;

	fprintf(fp, "Interface         State     Querier          Timeout Version=\n");
	for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
		char timeout[10];
		int version;

		if (!ifi->ifi_querier) {
			inet_fmt(ifi->ifi_curr_addr, s1, sizeof(s1));
			snprintf(timeout, sizeof(timeout), "None");
		} else {
			inet_fmt(ifi->ifi_querier->al_addr, s1, sizeof(s1));
			snprintf(timeout, sizeof(timeout), "%u", router_timeout -
				 pev_timer_get(ifi->ifi_querier->al_timerid));
		}

		if (ifi->ifi_flags & IFIF_IGMPV1)
			version = 1;
		else if (ifi->ifi_flags & IFIF_IGMPV2)
			version = 2;
		else
			version = 3;

		fprintf(fp, "%-16s  %-8s  %-15s  %7s %7d\n", ifi->ifi_name,
			ifstate(ifi), s1, timeout, version);
	}

	return 0;
}

static int show_status(FILE *fp)
{
	fprintf(fp, "Process ID                         : %d\n", getpid());
	fprintf(fp, "Query interval, sec (QI)           : %d\n", igmp_query_interval);
	fprintf(fp, "Query response interval, sec (QRI) : %d\n", igmp_response_interval);
	fprintf(fp, "Last member interval               : %d\n", igmp_last_member_interval);
	fprintf(fp, "Robustness (QRV)                   : %d\n", igmp_robustness);
	fprintf(fp, "Router timeout                     : %d\n", router_timeout);
	fprintf(fp, "Router alert (IP header opt)       : %s\n", ENABLED(router_alert));

	return 0;
}

static int show_version(FILE *fp)
{
	fputs(versionstring, fp);
	return 0;
}

static void ipc_help(int sd, char *buf, size_t len)
{
	FILE *fp;

	fp = tempfile();
	if (!fp) {
		int sz;

		sz = snprintf(buf, len, "Cannot create tempfile: %s", strerror(errno));
		if (write(sd, buf, sz) != sz)
			logit(LOG_INFO, errno, "Client closed connection");
		return;
	}

	for (size_t i = 0; i < NELEMS(cmds); i++) {
		struct ipcmd *c = &cmds[i];
		char tmp[50];

		snprintf(tmp, sizeof(tmp), "%s%s%s", c->cmd, c->arg ? " " : "", c->arg ?: "");
		fprintf(fp, "%s\t%s\n", tmp, c->help ? c->help : "");
	}
	rewind(fp);

	while (fgets(buf, len, fp)) {
		if (!ipc_write(sd, buf, strlen(buf)))
			continue;

		logit(LOG_WARNING, errno, "Failed communicating with client");
	}

	fclose(fp);
}

static void ipc_handle(int sd, void *arg)
{
	char cmd[768] = { 0 };
	ssize_t len;
	int client;
	int rc = 0;

	client = accept(sd, NULL, NULL);
	if (client < 0)
		return;

	switch (ipc_read(client, cmd, sizeof(cmd))) {
	case IPC_HELP:
		ipc_help(client, cmd, sizeof(cmd));
		break;

	case IPC_VERSION:
		ipc_show(client, show_version, cmd, sizeof(cmd));
		break;
#if 0
	case IPC_IGMP_GRP:
		ipc_show(client, show_igmp_groups, cmd, sizeof(cmd));
		break;

	case IPC_IGMP_IFACE:
		ipc_show(client, show_igmp_iface, cmd, sizeof(cmd));
		break;

	case IPC_IGMP:
		ipc_show(client, show_igmp, cmd, sizeof(cmd));
		break;
#endif
	case IPC_IGMP:
		ipc_show(client, show_igmp, cmd, sizeof(cmd));
		break;

	case IPC_STATUS:
		ipc_show(client, show_status, cmd, sizeof(cmd));
		break;

	case IPC_OK:
		/* client ping, ignore */
		break;

	case IPC_ERR:
		logit(LOG_WARNING, errno, "Failed reading command from client");
		rc = IPC_ERR;
		break;

	default:
		logit(LOG_WARNING, 0, "Invalid IPC command: %s", cmd);
		break;
	}

	if (rc == IPC_ERR)
		ipc_err(sd, cmd, sizeof(cmd));

	ipc_close(client);
}


void ipc_init(char *sockfile)
{
	socklen_t len;
	int sd;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0) {
		logit(LOG_ERR, errno, "Failed creating IPC socket");
		return;
	}

	/* Portable SOCK_NONBLOCK replacement, ignore any error. */
	(void)fcntl(sd, F_SETFD, fcntl(sd, F_GETFD) | O_NONBLOCK);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sun.sun_family = AF_UNIX;
	if (sockfile)
		strlcpy(sun.sun_path, sockfile, sizeof(sun.sun_path));
	else
		snprintf(sun.sun_path, sizeof(sun.sun_path), _PATH_QUERIERD_SOCK, ident);

	unlink(sun.sun_path);
	logit(LOG_DEBUG, 0, "Binding IPC socket to %s", sun.sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (bind(sd, (struct sockaddr *)&sun, len) < 0 || listen(sd, 1)) {
		logit(LOG_WARNING, errno, "Failed binding IPC socket, client disabled");
		close(sd);
		return;
	}

	ipc_sockid = pev_sock_add(sd, ipc_handle, NULL);
	if (ipc_sockid == -1)
		logit(LOG_ERR, 0, "Failed registering IPC handler");

	ipc_socket = sd;
}

void ipc_exit(void)
{
	if (ipc_sockid > 0)
		pev_sock_del(ipc_sockid);
	if (ipc_socket > -1)
		close(ipc_socket);

	unlink(sun.sun_path);
	ipc_socket = -1;
	ipc_sockid = 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
