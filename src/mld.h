/* SPDX-License-Identifier: ISC */

#ifndef MCD_MLD_H_
#define MCD_MLD_H_

#include <netinet/icmp6.h>

#define MLDV2_LISTENER_REPORT	143

struct mldv2_query {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    uint16_t mrc;		/* Maximum Response Code      */
    uint16_t resv;
    struct in6_addr group;
    uint8_t  qrv;		/* Resv:4 S:1 QRV:3           */
    uint8_t  qqic;
    uint16_t nsrcs;
    struct in6_addr srcs[0];
};

extern void		accept_mld(struct ifi *, int, uint8_t *, size_t);
extern void		send_mld_query(const struct ifi *, int, const inet_addr_t *);

#endif /* MCD_MLD_H_ */
