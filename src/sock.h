/* SPDX-License-Identifier: ISC */

#ifndef MCD_SOCK_H_
#define MCD_SOCK_H_

#define RECV_BUF_SIZE 1536

extern uint8_t		*recv_buf;
extern uint8_t		*send_buf;

extern void		sock_init(void);
extern void		sock_exit(void);
extern void		sock_iface_init(struct ifi *);
extern void		sock_iface_exit(struct ifi *);
extern size_t		build_ether(uint8_t *, const struct ifi *, const uint8_t *, uint16_t);
extern int		sock_send(const struct ifi *, size_t);
extern int		mcast_join(const struct ifi *, const inet_addr_t *);
extern void		sock_reload_begin(void);
extern void		sock_reload_end(void);

#endif /* MCD_SOCK_H_ */
