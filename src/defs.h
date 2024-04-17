/* SPDX-License-Identifier: ISC */

#ifndef MCD_DEFS_H_
#define MCD_DEFS_H_

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#define _LINUX_IN_H             /* For Linux <= 2.6.25 */
#include <linux/types.h>
#include <linux/mroute.h>
#if defined(HAVE_STRLCPY)
#include <string.h>
#endif
#if defined(HAVE_STRTONUM)
#include <stdlib.h>
#endif
#if defined(HAVE_PIDFILE)
#include <libutil.h>
#endif

typedef void (*cfunc_t) (void*);
typedef void (*ihfunc_t) (int);

#include "iface.h"
#include "igmp.h"
#include "pathnames.h"
#include "pev.h"

#define NELEMS(a)	(sizeof((a)) / sizeof((a)[0]))
#define ENABLED(v)      (v ? "Enabled" : "Disabled")

TAILQ_HEAD(ifaces, ifi);

/*
 * External declarations for global variables and functions.
 */
#define RECV_BUF_SIZE 1536
extern uint8_t		*recv_buf;
extern uint8_t		*send_buf;
extern int		router_alert;
extern uint32_t		router_timeout;
extern uint32_t		allhosts_group;
extern uint32_t		allrtrs_group;
extern uint32_t		allreports_group;
extern uint32_t		igmp_response_interval;
extern uint32_t		igmp_query_interval;
extern uint32_t		igmp_last_member_interval;
extern uint32_t		igmp_robustness;

extern int		loglevel;
extern int		use_syslog;
extern int		running;
extern int		haveterminal;
extern int		did_final_init;

/*
 * Limit on length of route data
 */
#define MAX_IP_PACKET_LEN	576
#define MIN_IP_HEADER_LEN	20
#define IP_HEADER_RAOPT_LEN	(router_alert ? 24 : 20)
#define MAX_IP_HEADER_LEN	60
#define MAX_DVMRP_DATA_LEN \
		( MAX_IP_PACKET_LEN - MAX_IP_HEADER_LEN - IGMP_MINLEN )

/* NetBSD 6.1, for instance, does not have IPOPT_RA defined. */
#ifndef IPOPT_RA
#define IPOPT_RA		148
#endif

/*
 * The IGMPv2 <netinet/in.h> defines INADDR_ALLRTRS_GROUP, but earlier
 * ones don't, so we define it conditionally here.
 */
#ifndef INADDR_ALLRTRS_GROUP
					/* address for multicast mtrace msg */
#define INADDR_ALLRTRS_GROUP	(uint32_t)0xe0000002	/* 224.0.0.2 */
#endif

#ifndef INADDR_ALLRPTS_GROUP
#define INADDR_ALLRPTS_GROUP    ((in_addr_t)0xe0000016) /* 224.0.0.22, IGMPv3 */
#endif

#ifndef INADDR_MAX_LOCAL_GROUP
#define INADDR_MAX_LOCAL_GROUP	(uint32_t)0xe00000ff	/* 224.0.0.255 */
#endif


/* main.c */
extern char	       *ident;
extern char	       *prognm;
extern char	       *config_file;
extern const char      *versionstring;
extern int		cache_lifetime;
extern int		prune_lifetime;
extern int		mrt_table_id;
extern void             restart(void);

/* log.c */
extern void             log_init(char *);
extern int		log_str2lvl(char *);
extern const char *	log_lvl2str(int);
extern int		log_list(char *, size_t);
extern void		logit(int, int, const char *, ...);
extern void             resetlogging(void *);

/* igmp.c */
extern void		igmp_init(void);
extern void		igmp_exit(void);
extern void		igmp_iface_init(struct ifi *);
extern void		igmp_iface_exit(struct ifi *);
extern void		accept_igmp(int, uint8_t *, size_t);
extern size_t		build_igmp(uint8_t *, uint32_t, uint32_t, int, int, uint32_t, int);
extern void		send_igmp(const struct ifi *, uint32_t, int, int, uint32_t, int);
extern char *		igmp_packet_kind(uint32_t, uint32_t);
extern int		igmp_debug_kind(uint32_t, uint32_t);

/* iface.c */
extern void		iface_init(void);
extern void		iface_zero(struct ifi *);
extern void             iface_add(int, int);
extern void             iface_del(int, int);
extern void             iface_check_election(struct ifi *);
extern void             iface_check(int, unsigned int);
extern void		iface_check_state(void);
extern void		iface_exit(void);
extern void		accept_group_report(int, uint32_t, uint32_t, uint32_t, int);
extern void		accept_leave_message(int, uint32_t, uint32_t, uint32_t);
extern void		accept_membership_query(int, uint32_t, uint32_t, uint32_t, int, int, int);
extern void             accept_membership_report(int, uint32_t, uint32_t, struct igmpv3_report *, ssize_t);

/* netlink.c */
extern void             netlink_init(void);
extern void             netlink_exit(void);

/* config.c */
extern void             config_init(void);
extern void		config_set_ifflag(uint32_t);
extern struct ifi      *config_iface_iter(int);
extern struct ifi      *config_iface_add(char *);
extern struct ifi      *config_iface_vlan(struct ifi *, int);
extern void             config_iface_addr_del(int, struct sockaddr *);
extern struct ifi      *config_find_ifname(char *);
extern struct ifi      *config_find_ifaddr(in_addr_t);
extern struct ifi      *config_find_iface(int);
extern struct ifi      *config_init_tunnel(in_addr_t, in_addr_t, uint32_t);
extern void             config_iface_addr_add(int, struct sockaddr *, unsigned int);
extern void		config_iface_init(void);

/* cfparse.y */
extern int		config_parse(const char *file);

/* inet.c */
extern int		inet_valid_group(uint32_t);
extern int		inet_valid_host(uint32_t);
extern int		inet_valid_mask(uint32_t);
extern int		inet_valid_subnet(uint32_t, uint32_t);
extern char            *inet_name(uint32_t, int);
extern char            *inet_fmt(uint32_t, char *, size_t);
extern char            *inet_fmts(uint32_t, uint32_t, char *, size_t);
extern uint32_t		inet_parse(char *, int);
extern int		inet_cksum(uint16_t *, uint32_t);

/* ipc.c */
extern void             ipc_init(char *);
extern void             ipc_exit(void);

/* lib/ */
#ifndef HAVE_STRLCPY
extern size_t		strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
extern size_t		strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRTONUM
extern long long	strtonum(const char *numstr, long long minval, long long maxval, const char **errstrp);
#endif

#ifndef HAVE_TEMPFILE
extern FILE *		tempfile(void);
#endif

#ifndef HAVE_PIDFILE
extern int		pidfile(const char *basename);
#endif

static inline char *chomp(char *str)
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

#endif /* MCD_DEFS_H_ */
