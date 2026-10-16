/* SPDX-License-Identifier: ISC */

#ifndef MCD_INET_H_
#define MCD_INET_H_

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Checks if addr is IPv4LL
 */
#ifndef IN_LINKLOCAL
#define IN_LINKLOCALNETNUM 0xa9fe0000
#define IN_LINKLOCAL(addr) ((addr & IN_CLASSB_NET) == IN_LINKLOCALNETNUM)
#endif

#ifdef AF_INET6
#define INET_ADDRSTR_LEN  INET6_ADDRSTRLEN
#else
#define INET_ADDRSTR_LEN  INET_ADDRSTRLEN
#endif

extern char s1[INET_ADDRSTR_LEN];
extern char s2[INET_ADDRSTR_LEN];
extern char s3[INET_ADDRSTR_LEN];
extern char s4[INET_ADDRSTR_LEN];

/*
 * Replace in_addr_t with family agnostic type
 */
typedef struct sockaddr_storage inet_addr_t;

/*
 * External function declarations
 */
extern int		inet_addr_cmp(const inet_addr_t *, const inet_addr_t *);
extern int		inet_addr_linklocal(const inet_addr_t *);
extern void		inet_addr_set(inet_addr_t *, const struct sockaddr *);
extern uint32_t		inet_addr_get4(const inet_addr_t *);
extern char	       *inet_addr_fmt(const inet_addr_t *, char *, size_t);
extern void		inet_addr_set4(inet_addr_t *, uint32_t);
extern void		inet_addr_set6(inet_addr_t *, const struct in6_addr *);
extern const struct in6_addr *inet_addr_get6(const inet_addr_t *);
extern int		inet_addr_is_any(const inet_addr_t *);
extern int		inet_addr_is_group(const inet_addr_t *);
extern int		inet_addr_is_lanscope(const inet_addr_t *);
extern void		inet_addr_any(inet_addr_t *, int);
extern int		inet_valid_group(uint32_t);
extern int		inet_valid_host(uint32_t);
extern int		inet_valid_mask(uint32_t);
extern int		inet_valid_subnet(uint32_t, uint32_t);
extern char            *inet_name(uint32_t, int);
extern char            *inet_fmt(uint32_t, char *, size_t);
extern char            *inet_fmts(uint32_t, uint32_t, char *, size_t);
extern uint32_t		inet_parse(char *, int);
extern int		inet_cksum(uint16_t *, uint32_t);

#endif /* MCD_INET_H_ */
