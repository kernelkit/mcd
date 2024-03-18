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

#endif /* MCD_INET_H_ */
