/* SPDX-License-Identifier: ISC */

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "defs.h"
#include "inet.h"
#include "ipc.h"
#include "queue.h"

#define SYSFS_PATH_ "/sys/class/net/"

struct port_name {
	TAILQ_ENTRY(port_name) link;
	char ifname[IFNAMSIZ + 1];
};
TAILQ_HEAD(port_name_list, port_name); 
struct port_name_list pnl = TAILQ_HEAD_INITIALIZER(pnl);

struct mdb {
	TAILQ_ENTRY(mdb) link;

	char br[IFNAMSIZ + 1];
	char group[64];
	char port[576];		/* 18 chars per port * 32 ports */
	int  vid;
};


TAILQ_HEAD(, mdb) mdb_list = TAILQ_HEAD_INITIALIZER(mdb_list);
static int compat = 0;

static struct mdb *find(char *group, int vid)
{
	struct mdb *e;

	TAILQ_FOREACH(e, &mdb_list, link) {
		if (!strcmp(group, e->group) && vid == e->vid)
			return e;
	}

	return NULL;
}

static struct mdb *alloc(void)
{
	struct mdb *e;

	e = calloc(1, sizeof(struct mdb));
	if (!e)
		return NULL;

	TAILQ_INSERT_TAIL(&mdb_list, e, link);

	return e;
}

static void drop(void)
{
	struct mdb *e, *tmp;

	TAILQ_FOREACH_SAFE(e, &mdb_list, link, tmp) {
		TAILQ_REMOVE(&mdb_list, e, link);
		free(e);
	}
}

static char *bridge_path(const char *brname, char *setting)
{
	static char path[512];

	snprintf(path, sizeof(path), SYSFS_PATH_"%s/bridge/%s", brname, setting);

	return path;
}

static int populate(void)
{
	struct mdb *e;
	FILE *fp;
	char buf[80];
	int num = 0;

	fp = popen("bridge mdb show", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		char br[IFNAMSIZ + 1], port[IFNAMSIZ + 3], group[64];
		char *tok, *dst;
		int vid = 0;
		size_t len;

		for (tok = strtok(buf, " \t"); tok; tok = strtok(NULL, " \t")) {
			if (!strcmp(tok, "dev")) {
				dst = br;
				len = sizeof(br);
			} else if (!strcmp(tok, "port")) {
				dst = port;
				len = sizeof(port);
			} else if (!strcmp(tok, "grp")) {
				dst = group;
				len = sizeof(group);
			} else if (!strcmp(tok, "vid")) {
				tok = strtok(NULL, " \t");
				vid = strtol(tok, NULL, 10);
				continue;
			} else {
				continue;
			}

			tok = strtok(NULL, " \t");
			strlcpy(dst, tok, len);
		}

		e = find(group, vid);
		if (!e) {
			e = alloc();
			if (!e) {
				logit(LOG_ERR, errno, "Failed allocating mdb entry");
				break;
			}
		}

		if (e->port[0])
			strcat(e->port, ", ");
		if (json)
			strcat(e->port, "\"");
		strcat(e->port, port);
		if (json)
			strcat(e->port, "\"");
		strlcpy(e->br, br, sizeof(e->br));
		strlcpy(e->group, group, sizeof(e->group));
		e->vid = vid;
		num++;
	}

	return pclose(fp);
}

static int value(char *path)
{
	FILE *fp;
	int val, n;

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	n = fscanf(fp, "%d", &val);
	fclose(fp);

	return val;
}

static int has(char *path, char *setting)
{
	char  file[512];

	if (snprintf(file, sizeof(file), "%s/%s", path, setting) >= (int)sizeof(file)) {
		logit(LOG_WARNING, 0, "Internal buffer overflow, cannot read value of %s/%s", path, setting);
		return 0;
	}
	logit(LOG_DEBUG, 0, "Has %s", file);

	return value(file);
}

static char *got(const char *brname, char *prop, int setval, int first)
{
	struct dirent *d;
	static char path[256];
	static DIR *dir = NULL;

	logit(LOG_DEBUG, 0, "Checking %s for property %s ...", brname, prop);
	if (first) {
		if (dir)
			closedir(dir);

		snprintf(path, sizeof(path), SYSFS_PATH_"%s/brif", brname);
		logit(LOG_DEBUG, 0, "Opening %s to figure out %s ports ...", path, brname);
		dir = opendir(path);
		if (!dir) {
			logit(LOG_WARNING, errno, "Failed listing %s ports", brname);
			return NULL;
		}
	}

	while ((d = readdir(dir))) {
		char ifpath[512];

		if (DT_LNK != d->d_type)
			continue;

		snprintf(ifpath, sizeof(ifpath), "%s/%s", path, d->d_name);
		if (has(ifpath, prop) == setval)
			return d->d_name;
	}

	closedir(dir);
	dir = NULL;

	return NULL;
}

static int cmpstringp(const void *p1, const void *p2)
{
	const char *str1 = *(const char **)p1;
	const char *str2 = *(const char **)p2;
	size_t str1_len = strlen(str1);
	size_t str2_len = strlen(str2);
	size_t index, length;

	if (str1_len == str2_len) {
		length = str1_len;
		return strncmp(str1, str2, length);
	}

	if (str1_len > str2_len)
		length = str1_len;
	else 
		length = str2_len;
	
	for (index = 0; index <= length; index++) {
		if (*str1 != *str2)
			break;

		str1++;
		str2++;
	}

	if (index <= 2)
		return strncmp(str1, str2, length);

	if (str1_len < str2_len)
		return -1;

	return 1;
}

void bridge_prop(FILE *fp, const char *brname, char *prop, int setval)
{
	struct port_name *name = NULL, *next = NULL;
	const size_t len = IFNAMSIZ + 3;
	char **array = NULL;
	char *ifname;
	int num = 0;
	int x = 0;

	while ((ifname = got(brname, prop, setval, !num))) {
		name = calloc(1, sizeof(struct port_name));
		if (!name)
			goto out;

		strlcpy(name->ifname, ifname, sizeof(name->ifname));
		logit(LOG_DEBUG, 0, "Loop, name %s", name->ifname);

		TAILQ_INSERT_TAIL(&pnl, name, link);	
		num++;
		name = NULL;
	}

	array = calloc(num, sizeof(char *));
	if (!array)
		goto out;

	for (int j = 0; j < num; j++) {
		array[j] = malloc(len * sizeof(char));
		if (!array[j])
			goto out;
	}
	
	TAILQ_FOREACH(name, &pnl, link) {
		logit(LOG_DEBUG, 0, "Foreach, port name: %s", name->ifname);
		if (json)
			snprintf(array[x], len, "\"%s\"", name->ifname);
		else
			strlcpy(array[x], name->ifname, len);
		x++;
	}

	qsort(array, num, sizeof(char *), cmpstringp);

	for (int i = 0; i < num; i++) {
		logit(LOG_DEBUG, 0, "Array val: %s, index: %d", array[i], i);
		fprintf(fp, "%s%s", i ? ", " : " ", array[i]);
	}

out:
	/* Cleaning up */
	if (array) {
		for (int j = 0; j < num; j++) {
			if (array[j]) 
				free(array[j]);
		}

		free(array);
	}

	for (name = TAILQ_FIRST(&pnl); name; name = next) {
		next = TAILQ_NEXT(name, link);
		TAILQ_REMOVE(&pnl, name, link);
		free(name);
	}

	if (!json) {
		if (!num && compat)
			fprintf(fp, "---");
		fprintf(fp, "\n");
	}
}

/*
 * Parse output from bridge -s -json vlan global:
 * > bridge -s -json vlan global show br0 | jq
 * [
 *   {
 *     "ifname": "br0",
 *     "vlans": [
 *       {
 *         "vlan": 1,
 *         ...
 *         "router_ports": [
 *           {
 *             "port": "eth0",
 *             "timer": "  29.01",
 *             "type": "temp"
 *           }
 *         ]
 *       },
 *       {
 *         "vlan": 2,
 *         ...
 *         "router_ports": [
 *           {
 *             "port": "eth1",
 *             "timer": "  19.04",
 *             "type": "temp"
 *           }
 *         ]
 *       }
 *     ]
 *   }
 * ]
 */
void bridge_router_ports(FILE *fp, const char *brname)
{
	static const char *bridge_args = "-json -s vlan global show dev";
	static const char *jq_filter = ".[].vlans[] | " \
				       "if has(\"router_ports\") == true then .router_ports[].port + \" \" + " \
					   ".router_ports[].timer + \" \" + .router_ports[].type else \"false\" end";
	char prev_ifname[20] = { 0 };
	char cmd[300], buf[80];
	int num = 0;
	FILE *rfp;
	int ret;

	ret = snprintf(cmd, sizeof(cmd), "bridge %s %s | jq -r '%s' | sort",
		       bridge_args, brname, jq_filter);

	if (ret < 0 || ret >= (int)sizeof(cmd))
		goto fail;
	
	rfp = popen(cmd, "r");

	if (!rfp)
		goto fail;

	while (fgets(buf, sizeof(buf), rfp)) {
		char ifname[20];
		int seen = 0;
		float timer;

		if (sscanf(buf, "%19s %2f temp", ifname, &timer) != 2)
			continue;

		seen = prev_ifname[0] && !strncmp(ifname, prev_ifname, sizeof(ifname));

		logit(LOG_DEBUG, 0, "Found router port %s with %.2f s timeout\n", ifname, timer);
		if (timer > 0.0 && !seen) {
			if (json)
				fprintf(fp, "%s\"%s\"", num ? ", " : " ", ifname);
			else
				fprintf(fp, "%s%s", num ? ", " : " ", ifname);
			num++;
			memcpy(prev_ifname, ifname, sizeof(prev_ifname));
		}
	}
	pclose(rfp);

fail:
	if (!json) {
		if (!num && compat)
			fprintf(fp, "---");
		fprintf(fp, "\n");
	}
}

static int enabled(const char *brname)
{
	return value(bridge_path(brname, "multicast_snooping"));
}

/*
 * Dumpster diving in the ARP cache and the bridge's FDB to figure out
 * the MAC address of a given IP, and which port we learned it on.
 */
static void dumpster(char *addr, char *mac, size_t mlen, char *port, size_t plen)
{
	char lladdr[20] = { 0 };
	int found = 0;
	char buf[256];
	char *ptr;
	FILE *pp;

	if (mac)
		strlcpy(mac, "00:c0:ff:ee:00:01", mlen);
	if (port)
		strlcpy(port, "N/A", plen);

	pp = popen("ip neigh", "r");
	if (pp) {
		while (fgets(buf, sizeof(buf), pp)) {
			logit(LOG_DEBUG, 0, "line: %s", buf);
			ptr = strpbrk(buf, " \t\n");
			if (!ptr)
				continue;

			*ptr++ = 0;
			logit(LOG_DEBUG, 0, "line ip '%s' vs addr '%s'", buf, addr);
			if (strcmp(buf, addr))
				continue;

			logit(LOG_DEBUG, 0, "Searching line %s for lladdr", ptr);
			ptr = strstr(ptr, "lladdr");
			if (!ptr)
				continue;

			strlcpy(lladdr, &ptr[7], sizeof(lladdr));
			ptr = strpbrk(lladdr, " \t\n");
			if (ptr)
				*ptr = 0;
			if (mac)
				strlcpy(mac, lladdr, mlen);
			found = 1;
			break;
		}
		pclose(pp);
	}

	if (!found)
		return;

	pp = popen("bridge fdb", "r");
	if (pp) {
		while (fgets(buf, sizeof(buf), pp)) {
			logit(LOG_DEBUG, 0, "line: %s", buf);
			if (strncmp(buf, lladdr, 17))
				continue;

			ptr = strstr(buf, "dev");
			if (ptr && port) {
				strlcpy(port, &ptr[4], plen);
				ptr = strpbrk(port, " \t\n");
				if (ptr)
					*ptr = 0;
			}
			break;
		}
		pclose(pp);
	}
}

static int is_frnt_vlan(int vid)
{
	switch (vid) {
	case 4020:
		/* fallthrough */
	case 4021:
		/* fallthrough */
	case 4022:
		/* fallthrough */
	case 4032:
		/* fallthrough */
	case 4033:
		return 1;

	default:
		break;
	}

	return 0;
}

/*
 * For compatibility with output from WeOS 5 igmp tool, which in turn
 * was made to emulate the output of the WeOS 4 igmpd.
 */
int show_bridge_compat(FILE *fp)
{
	struct ifi *ifi;
	struct mdb *e;
	int num, vnum;

	/* Hard-coded to a single bridge */
	if (!enabled("br0")) {
		fprintf(fp, "IGMP/MLD snooping is disabled.\n");
		return 0;
	}

	/* Change output to match WeOS closely */
	compat = 1;

	/*
	 * fast_leave brif => 1
	 * static router ports brif =>2
	 * discovered router ports => multicast_router_ports  timer != 0
	 * multicast flooded on    => multicast_flood
	 */
	fprintf(fp, " Static Multicast ports=\n");
	fprintf(fp, " %-26s : ", "IGMP Fast Leave ports");      bridge_prop(fp, "br0", "multicast_fast_leave", 1);
	fprintf(fp, " %-26s : ", "Static router ports");        bridge_prop(fp, "br0", "multicast_router", 2);
	fprintf(fp, " %-26s : ", "Discovered router ports");    bridge_router_ports(fp, "br0");
	if (detail) {
		fprintf(fp, " %-26s : ---\n", "Dual Homing/Coupling ports");
		fprintf(fp, " %-26s : ---\n", "FRNT ring ports");
	}
	fprintf(fp, " %-26s : ", "Multicast flooded on ports"); bridge_prop(fp, "br0", "multicast_flood", 1);

	/*
	 *  VID  Querier IP       Querier MAC        Port     Interval  Timeout
	 * -------------------------------------------------------------------------------
	 *    1  192.168.2.20     00:07:7c:00:33:41  Eth 3      12 sec  299 sec
	 * 1337  192.168.13.37    00:07:7c:00:33:44  Eth 3      12 sec  299 sec
	 */
	fprintf(fp, "\n");
	if (detail)
		fprintf(fp, " VID  Querier IP       Querier MAC        Port              Interval  Timeout=\n");
	else
		fprintf(fp, " VID  Querier IP       Port              Timeout=\n");

	vnum = 0;
	for (ifi = config_iface_iter(1); ifi; ifi = config_iface_iter(0)) {
		char mac[20], port[20], dev[10];
		int len, vid, timeout;
		time_t now;
		char *ptr;

		len = snprintf(dev, sizeof(dev), "%s.", "br0");
		if (!strncmp(ifi->ifi_name, "vlan", 4))
			ptr = &ifi->ifi_name[4];
		else if (!strncmp(ifi->ifi_name, dev, len))
			ptr = &ifi->ifi_name[len];
		else
			ptr = ifi->ifi_name;
		vid = atoi(ptr);

		if (is_frnt_vlan(vid))
			continue;

		vnum++;
		if (!ifi->ifi_querier) {
			inet_fmt(ifi->ifi_inaddr, s1, sizeof(s1));
			fprintf(fp, "%4d  %-15s  LOCAL\n", vid, s1);
			continue;
		}

		inet_fmt(ifi->ifi_querier->al_addr, s1, sizeof(s1));
		now = time(NULL);
		timeout = router_timeout - (now - ifi->ifi_querier->al_ctime);
		dumpster(s1, mac, sizeof(mac), port, sizeof(port));

		if (detail)
			fprintf(fp, "%4d  %-15s  %-17s  %-16s  %4d sec  %d sec\n", vid, s1, mac, port, igmp_query_interval, timeout);
		else
			fprintf(fp, "%4d  %-15s  %-16s  %d sec\n", vid, s1, port, timeout);
	}

	/*
	 *  VID  Multicast Group  Filtered MAC Addr  Active ports
	 * -------------------------------------------------------------------------------
	 *    1  224.0.0.251      01:00:5E:00:00:FB  Eth 5
	 */
	if (populate()) {
		logit(LOG_ERR, 0, "Failed reading MDB");
		compat = 0;
		return 1;
	}

	fprintf(fp, "\n");
	fprintf(fp, " VID  Multicast Group  Filtered MAC Addr  Active ports=\n");

	num = 0;
	TAILQ_FOREACH(e, &mdb_list, link) {
		uint8_t mac[ETH_ALEN];
		struct in_addr ina;

		inet_aton(e->group, &ina);
		ETHER_MAP_IP_MULTICAST(&ina, mac);

		fprintf(fp, "%4d  %-15s  %02X:%02X:%02X:%02X:%02X:%02X  %s\n",
		       e->vid, e->group, mac[0], mac[1], mac[2],
		       mac[3], mac[4], mac[5], e->port);

		num++;
	}

	/*
	 * Trailer, only for WeOS 4 compat use
	 * XXX: How to get MAX groups and unique VLANs?
	 */
	if (detail)
		fprintf(fp, "\n=\nTotal: %d filters, max 2048, in %d VLANs.\n", num, vnum);

	drop();
	compat = 0;

	return 0;
}

int show_bridge_groups(FILE *fp)
{
	struct mdb *e;
	int first = 1;

	if (populate()) {
		logit(LOG_ERR, 0, "Failed reading MDB");
		return 1;
	}

	if (json) {
		fprintf(fp, "[");
		prefix += 2;
	}
	else
		fprintf(fp, "Bridge          VID  Multicast Group       Ports=\n");

	TAILQ_FOREACH(e, &mdb_list, link) {
		char ena[20], vid[11] = { 0 };
		unsigned char mac[ETH_ALEN];
		int once = 1;
		char *group;

		if (strchr(e->group, ':')) {
			if (strncmp(e->group, "ff", 2)) {
				strlcpy(ena, e->group, sizeof(ena));
				group = ena;
#ifdef AF_INET6
			} else {
				struct in6_addr in6a;

				inet_pton(AF_INET6, e->group, &in6a);
				mac[0] = 0x33;
				mac[1] = 0x33;
				memcpy(mac + 2, &in6a.s6_addr[12], 4);
				snprintf(ena, sizeof(ena), "%02x:%02x:%02x:%02x:%02x:%02x",
					 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				group = e->group;
#endif
			}
		} else {
			struct in_addr ina;

			inet_aton(e->group, &ina);
			ETHER_MAP_IP_MULTICAST(&ina, mac);
			snprintf(ena, sizeof(ena), "%02x:%02x:%02x:%02x:%02x:%02x",
				 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			group = e->group;
		}

		if (e->vid > 0)
			snprintf(vid, sizeof(vid), "%4d", e->vid);
		else
			snprintf(vid, sizeof(vid), "%4s", "");

		if (json) {
			fprintf(fp, "%s%*s{\n", first ? "\n" : ",\n", prefix, "");
			prefix += 2;
			first = 0;

			jprint(fp, "bridge", e->br, &once);
			if (e->vid > 0)
				jprinti(fp, "vid", e->vid, &once);
			jprint(fp, "group", e->group, &once);
			jprint(fp, "mac", ena, &once);
			jprinta(fp, "ports", e->port, &once);

			prefix -= 2;
			fprintf(fp, "\n%*s}", prefix, "");
		} else
			fprintf(fp, "%-15s%s  %-20s  %s\n", e->br, vid, group, e->port);
	}

	if (json) {
		prefix -= 2;
		if (first)
			fprintf(fp, "]\n");
		else
			fprintf(fp, "\n%*s]\n", prefix, "");
	}

	drop();

	return 0;
}

