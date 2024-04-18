/* SPDX-License-Identifier: ISC */

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
 *           echo "help" |socat - UNIX-CONNECT:/run/mcd.sock
 */

#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>

#include "bridge.h"
#include "defs.h"
#include "inet.h"
#include "ipc.h"

static struct sockaddr_un sun;
static int ipc_sockid =  0;
static int ipc_socket = -1;
int detail = 0;
int json = 0;
int prefix = 0;
int nested = 0;

enum {
	IPC_ERR = -1,
	IPC_OK  = 0,
	IPC_HELP,
	IPC_VERSION,
	IPC_IGMP,
	IPC_IGMP_GRP,
	IPC_IGMP_IFACE,
	IPC_COMPAT,
	IPC_STATUS,
	IPC_MDB,
};

struct ipcmd {
	int   op;
	char *cmd;
	char *arg;
	char *help;
} cmds[] = {
	{ IPC_HELP,       "help", NULL, "This help text" },
	{ IPC_VERSION,    "version", NULL, "Show daemon version" },
	{ IPC_IGMP_GRP,   "show groups", "[json]", "Show IGMP/MLD group memberships" },
	{ IPC_IGMP_IFACE, "show interfaces", "[json]", "Show IGMP/MLD interface status" },
	{ IPC_STATUS,     "show status", "[json]", "Show daemon status (default)" },
	{ IPC_IGMP,       "show igmp", "[json]", "Show interfaces and group memberships" },
	{ IPC_MDB,        "show mdb", NULL, "Show multicast forwarding database" },
	{ IPC_COMPAT,     "show compat", "[detail]", "Show legacy output (test compat mode)" },
	{ IPC_IGMP,       "show", "[json]", NULL }, /* hidden default */
};


static size_t strip(char *cmd, size_t len)
{
	char *ptr = cmd + len;

	len = strspn(ptr, " \t\n");
	if (len > 0)
		ptr += len;

	len = strlen(ptr);
	memmove(cmd, ptr, len + 1);

	return len;
}

static void check_opts(char *cmd, size_t len)
{
	json = prefix = nested = 0; /* reset before each command */
	detail = 0;

	len = strip(cmd, len);
	while (len > 0) {
		if (!strncasecmp(cmd, "detail", len))
			detail = 1;
		else if (!strncasecmp(cmd, "json", len))
			json = 1;

		len = strip(cmd, len);
	}
}

static int ipc_read(int sd, char *cmd, ssize_t len)
{
	ssize_t num;

	while ((num = read(sd, cmd, len - 1)) == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			continue;
		default:
			break;
		}
		return IPC_ERR;
	}
	if (num == 0)
		return IPC_OK;

	cmd[num] = 0;
	chomp(cmd);
//	logit(LOG_DEBUG, 0, "IPC cmd: '%s'", cmd);

	for (size_t i = 0; i < NELEMS(cmds); i++) {
		struct ipcmd *c = &cmds[i];
		size_t clen = strlen(c->cmd);

		if (!strncasecmp(cmd, c->cmd, clen)) {
			check_opts(cmd, clen);
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

	if (ifi->ifi_flags & IFIF_PROXY_QUERIER)
		return "Proxy";

	return "Up";
}

static int show_status(FILE *fp)
{
	if (json) {
		int first = 1;

		if (!nested) {
			fprintf(fp, "{\n");
			prefix += 2;
		}

		jprinti(fp, "pid", getpid(), &first);
		jprinti(fp, "query-interval", igmp_query_interval, &first);
		jprinti(fp, "query-response-interval", igmp_response_interval, &first);
		jprinti(fp, "query-last-member-interval", igmp_last_member_interval, &first);
		jprinti(fp, "robustness", igmp_robustness, &first);
		jprinti(fp, "router-timeout", router_timeout, &first);
		jprintb(fp, "router-alert", router_alert, &first);

		if (!nested) {
			prefix -= 2;
			fprintf(fp, "\n%*s}", prefix, "");
		}
	} else {
		if (detail)
			fprintf(fp, "Process ID              : %d\n", getpid());
		fprintf(fp, "Query Interval (default): %d sec\n", igmp_query_interval);
		if (detail) {
			fprintf(fp, "Query Response Interval : %d sec\n", igmp_response_interval);
			fprintf(fp, "Last Member Interval    : %d\n", igmp_last_member_interval);
			fprintf(fp, "Robustness Value        : %d\n", igmp_robustness);
		}
		fprintf(fp, "Router Timeout          : %d\n", router_timeout);
		if (detail)
			fprintf(fp, "Router Alert            : %s\n", ENABLED(router_alert));
	}

	return 0;
}

static int show_igmp_iface(FILE *fp)
{
	struct ifi *ifi;
	int first = 1;

	if (json) {
		fprintf(fp, "[\n");
		prefix += 2;
	} else
		fprintf(fp, "Interface       VID  Querier                     State  Interval  Timeout  Ver=\n");

	for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
		int interval = ifi->ifi_query_interval, rt_tmo = -1;
		char timeout[10];
		int version;

		if (!ifi->ifi_querier) {
			inet_fmt(ifi->ifi_inaddr, s1, sizeof(s1));
			snprintf(timeout, sizeof(timeout), "None");
		} else {
			time_t t;

			inet_fmt(ifi->ifi_querier->al_addr, s1, sizeof(s1));
			interval = ifi->ifi_querier->al_interval;
			t = time(NULL) - ifi->ifi_querier->al_ctime;
			rt_tmo = (int)((time_t)router_timeout - t);
			snprintf(timeout, sizeof(timeout), "%d", rt_tmo);
		}

		if (ifi->ifi_flags & IFIF_IGMPV1)
			version = 1;
		else if (ifi->ifi_flags & IFIF_IGMPV2)
			version = 2;
		else
			version = 3;

		if (json) {
			const char *State = ifstate(ifi);
			char state[strlen(State) + 1];
			int once = 1;

			fprintf(fp, "%s%*s{\n", first ? "" : ",\n", prefix, "");
			prefix += 2;

			for (size_t i = 0; i <= strlen(State); i++)
				state[i] = tolower(State[i]);

			jprint(fp, "interface", ifi->ifi_name, &once);
			if (ifi->ifi_vlan)
				jprinti(fp, "vid", ifi->ifi_vlan, &once);
			jprint(fp, "state", state, &once);
			jprint(fp, "querier", s1, &once);
			if (rt_tmo > -1)
				jprinti(fp, "timeout", rt_tmo, &once);
			jprinti(fp, "interval", interval, &once);
			jprinti(fp, "version", version, &once);

			prefix -= 2;
			fprintf(fp, "\n%*s}", prefix, "");
			first = 0;
		} else {
			char vlan[5] = { 0 };

			if (ifi->ifi_vlan)
				snprintf(vlan, sizeof(vlan), "%4d", ifi->ifi_vlan);
			fprintf(fp, "%-15s%4s  %-23s  %8s  %8d  %7s  %3d\n", ifi->ifi_name,
				vlan, s1, ifstate(ifi), interval, timeout, version);
		}
	}

	if (json) {
		prefix -= 2;
		fprintf(fp, "\n%*s]", prefix, "");
	}

	return 0;
}

static int show_igmp(FILE *fp)
{
	int rc = 0;

	if (json) {
		fprintf(fp, "{\n");
		prefix += 2;
	} else
		fprintf(fp, "Multicast Overview=\n");

	nested = 1;
	show_status(fp);

	if (json) {
		fprintf(fp, ",\n%*s\"fast-leave-ports\": [", prefix, "");
		bridge_prop(fp, NULL, "fastleave");
		fprintf(fp, " ],\n");

		fprintf(fp, "%*s\"multicast-router-ports\": [", prefix, "");
		bridge_router_ports(fp, NULL);
		fprintf(fp, " ],\n");

		fprintf(fp, "%*s\"multicast-flood-ports\": [", prefix, "");
		bridge_prop(fp, NULL, "mcast_flood");
		fprintf(fp, " ]");
	} else {
		fprintf(fp, "%-23s :", "Fast Leave Ports"); bridge_prop(fp, NULL, "fastleave");
		fprintf(fp, "%-23s :", "Router Ports");     bridge_router_ports(fp, NULL);
		fprintf(fp, "%-23s :", "Flood Ports");      bridge_prop(fp, NULL, "mcast_flood");
		fprintf(fp, "\n");
	}

	if (json)
		fprintf(fp, ",\n%*s\"multicast-queriers\": ", prefix, "");

	rc += show_igmp_iface(fp);
	if (!json)
		fprintf(fp, "\n");

	if (json)
		fprintf(fp, ",\n%*s\"multicast-groups\": ", prefix, "");
	rc += show_bridge_groups(fp);

	if (json) {
		prefix -= 2;
		fprintf(fp, "}\n");
	}

	return rc;
}

/*
 * Silly wrapper around `bridge mdb show` to list group memberships in a
 * slightly different manner -- closer to "show fdb" in WeOS
 */
static int show_mdb(FILE *fp)
{
	const int devw = 6;	/* XXX: calculate width dynamically */
	char buf[256];
	FILE *pp;

	pp = popen("bridge mdb show", "r");
	if (!pp) {
		fprintf(fp, "Failed querying bridge for MDB entries: %s\n", strerror(errno));
		return 1;
	}

	fprintf(fp, "%-28s %4s %-*s %s=\n", "Group", "VLAN", devw, "Bridge", "Port(s)");
	while (fgets(buf, sizeof(buf), pp)) {
		char flags[16];
		char port[16];
		char dev[16];
		char grp[64];
		int vid, num;

		num = sscanf(buf, "dev %15s port %15s grp %63s %15s vid %d", dev, port, grp, flags, &vid);
		if (num < 5)
			fprintf(fp, "%-28s %4s %-*s %s\n", grp, "", devw, dev, port);
		else
			fprintf(fp, "%-28s %4d %-*s %s\n", grp, vid, devw, dev, port);
	}

	return pclose(pp);
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

	case IPC_IGMP_GRP:
		ipc_show(client, show_bridge_groups, cmd, sizeof(cmd));
		break;

	case IPC_IGMP_IFACE:
		ipc_show(client, show_igmp_iface, cmd, sizeof(cmd));
		break;

	case IPC_IGMP:
		ipc_show(client, show_igmp, cmd, sizeof(cmd));
		break;

	case IPC_MDB:
		ipc_show(client, show_mdb, cmd, sizeof(cmd));
		break;

	case IPC_COMPAT:
		ipc_show(client, show_bridge_compat, cmd, sizeof(cmd));
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
		snprintf(sun.sun_path, sizeof(sun.sun_path), _PATH_MCD_SOCK, ident);

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
