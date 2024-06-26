/* SPDX-License-Identifier: ISC */

#define SYSLOG_NAMES
#include "defs.h"
#include <stdarg.h>

#define LOG_MAX_MSGS	20	/* if > 20/minute then shut up for a while */
#define LOG_SHUT_UP	600	/* shut up for 10 minutes */

#ifndef INTERNAL_NOPRI
#define INTERNAL_NOPRI  0x10
#endif

CODE prionm[] =
{
	{ "none",    INTERNAL_NOPRI },		/* INTERNAL */
	{ "crit",    LOG_CRIT       },
	{ "alert",   LOG_ALERT      },
	{ "panic",   LOG_EMERG      },
	{ "error",   LOG_ERR        },
	{ "warning", LOG_WARNING    },
	{ "notice",  LOG_NOTICE     },
	{ "info",    LOG_INFO       },
	{ "debug",   LOG_DEBUG      },
	{ NULL, -1 }
};

int loglevel = LOG_NOTICE;
int logging  = 0;
static char *log_name = PACKAGE_NAME;


int log_str2lvl(char *level)
{
    int i;

    for (i = 0; prionm[i].c_name; i++) {
	size_t len = MIN(strlen(prionm[i].c_name), strlen(level));

	if (!strncasecmp(prionm[i].c_name, level, len))
	    return prionm[i].c_val;
    }

    return atoi(level);
}

const char *log_lvl2str(int val)
{
    int i;

    for (i = 0; prionm[i].c_name; i++) {
	if (prionm[i].c_val == val)
	    return prionm[i].c_name;
    }

    return "unknown";
}

int log_list(char *buf, size_t len)
{
    int i;

    memset(buf, 0, len);
    for (i = 0; prionm[i].c_name; i++) {
	if (i > 0)
	    strlcat(buf, ", ", len);
	strlcat(buf, prionm[i].c_name, len);
    }

    return 0;
}

/*
 * Open connection to syslog daemon and set initial log level
 */
void log_init(char *ident, int use_syslog)
{
    log_name = ident;
    if (!use_syslog)
	return;

    logging  = 1;
    openlog(ident, LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(loglevel));
}


void prinl(int syserr, const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", log_name);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    if (syserr)
	fprintf(stderr, ": %s\n", strerror(syserr));
    else
	fprintf(stderr, "\n");
}

/*
 * Log errors and other messages to the system log daemon and to stderr,
 * according to the severity of the message and the current debug level.
 * For errors of severity LOG_ERR or worse, terminate the program.
 */
void logger(int severity, int syserr, const char *format, ...)
{
    va_list ap;
    static char fmt[211] = "warning - ";
    char *msg;
    struct timeval now;
    time_t now_sec;
    struct tm *thyme;

    va_start(ap, format);
    vsnprintf(&fmt[10], sizeof(fmt) - 10, format, ap);
    va_end(ap);
    msg = (severity == LOG_WARNING) ? fmt : &fmt[10];

    if (!logging) {
	if (severity > loglevel)
	    return;

	/* Only OK use-case for unsafe gettimeofday(), logging. */
	gettimeofday(&now, NULL);
	now_sec = now.tv_sec;
	thyme = localtime(&now_sec);
//	if (!debug)
	    fprintf(stderr, "%s: ", log_name);
	fprintf(stderr, "%02d:%02d:%02d.%03ld %s", thyme->tm_hour,
		thyme->tm_min, thyme->tm_sec, now.tv_usec / 1000, msg);
	if (syserr == 0)
	    fprintf(stderr, "\n");
	else
	    fprintf(stderr, ": %s\n", strerror(syserr));

	return;
    }

    if (syserr != 0)
	syslog(severity, "%s: %s", msg, strerror(syserr));
    else
	syslog(severity, "%s", msg);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
