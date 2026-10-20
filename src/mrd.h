/* SPDX-License-Identifier: ISC */

#ifndef MCD_MRD_H_
#define MCD_MRD_H_

/* Multicast Router Discovery, RFC 4286 */
#define IGMP_MRD_ADVERT		0x30
#define ICMP6_MRD_ADVERT	151

enum { MRD_ADVERT, MRD_SOLICIT, MRD_TERM };

#define MRD_ADV_INTERVAL	20	/* AdvertisementInterval, sec        */
#define MRD_ADV_JITTER		(MRD_ADV_INTERVAL * 25000) /* 2.5 %, us  */
#define MRD_MAX_INITIAL_INTERVAL 2	/* MaxInitialAdvertisementInterval   */
#define MRD_MAX_INITIAL_ADVERTS	3	/* MaxInitialAdvertisements          */
#define MRD_MAX_RESPONSE_DELAY	2	/* Reply to a solicitation within    */

extern int		mrd_msg(const struct ifi *, int);
extern void		mrd_start(struct ifi *);
extern void		mrd_stop(struct ifi *);
extern void		mrd_accept(struct ifi *, int, const inet_addr_t *, const inet_addr_t *);

#endif /* MCD_MRD_H_ */
