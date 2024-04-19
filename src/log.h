/* SPDX-License-Identifier: ISC */

#ifndef MCD_LOG_H_
#define MCD_LOG_H_

#include <stdio.h>
#include <syslog.h>

#define logit(pri, eno, fmt, arg...) do {	\
	if (logging)				\
		logger(pri, eno, fmt, ##arg);	\
	else					\
		prinl(eno, fmt, ##arg);		\
} while (0)

#define err(fmt, arg...)   logit(LOG_ERR,     errno, fmt, ##arg)
#define errx(fmt, arg...)  logit(LOG_ERR,     0,     fmt, ##arg)
#define warn(fmt, arg...)  logit(LOG_WARNING, errno, fmt, ##arg)
#define warnx(fmt, arg...) logit(LOG_WARNING, 0,     fmt, ##arg)
#define note(fmt, arg...)  logit(LOG_NOTICE,  0,     fmt, ##arg)
#define info(fmt, arg...)  logit(LOG_INFO,    0,     fmt, ##arg)
#define dbg(fmt, arg...)   logit(LOG_DEBUG,   0,     fmt, ##arg)

extern int         logging;

extern void        log_init    (char *, int);
extern int	   log_str2lvl (char *);
extern const char *log_lvl2str (int);
extern int	   log_list    (char *, size_t);
extern void        prinl       (int, const char *fmt, ...);
extern void	   logger      (int, int, const char *, ...);

#endif /* MCD_LOG_H_ */

/**
 * Local Variables:
 *  c-file-style: "cc-mode"
 * End:
 */
