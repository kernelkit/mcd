%{
/*
 * Configuration file parser for mcd
 *
 * Written originally for mrouted by Bill Fenner, NRL, 1994
 * Adapted to queried by Joachim Wiberg, Westermo, 2022
 * Adapted to mcd by Joachim Wiberg, KernelKit, 2024
 *
 * cfparse.y,v 3.8.4.30 1998/03/01 01:48:58 fenner Exp
 */

#include <glob.h>
#include <stdio.h>
#include <stdarg.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "defs.h"
#include "inet.h"

/*
 * Local function declarations
 */
static void        fatal(const char *fmt, ...);
static void        warning(const char *fmt, ...);
static void        yyerror(char *s);
static char       *yytoken(void);
static int         yylex(void);
int                yyparse(void);

static FILE *yyin;
static int lineno;

static struct ifi *ifi;		/* AF_INET entry being parsed  */
static struct ifi *twin;	/* its AF_INET6 entry, if any  */
static struct ifi scrap;
static int off4, off6;		/* igmp off, mld off           */

/* Apply flag changes to both entries of the interface */
static void ifset(uint32_t set, uint32_t clr)
{
    ifi->ifi_flags = (ifi->ifi_flags & ~clr) | set;
    if (twin)
	twin->ifi_flags = (twin->ifi_flags & ~clr) | set;
}

%}

%union
{
    int       num;
    char     *ptr;
    uint32_t  addr, group;
    inet_addr_t ina;
};

%token GLOBAL_QUERY_INTERVAL GLOBAL_QUERY_LAST_MEMBER_INTERVAL GLOBAL_QUERY_RESPONSE_INTERVAL
%token QUERY_INTERVAL
%token IGMP_ROBUSTNESS ROUTER_TIMEOUT ROUTER_ALERT INCLUDE
%token NO PHYINT
%token DISABLE ENABLE IGMPV1 IGMPV2 IGMPV3 STATIC_GROUP PROXY_QUERIER
%token MLDV1 MLDV2 IGMP MLD
%token VLAN
%token <num> BOOLEAN
%token <num> NUMBER
%token <ptr> STRING
%token <addr> ADDR
%token <ina> GROUP

%start conf

%%

conf	: stmts
	;

stmts	: /* Empty */
	| stmts stmt
	;

stmt	: error
	| INCLUDE STRING
	{
	    glob_t gl = { 0 };

	    glob($2, 0, NULL, &gl);
	    for (size_t i = 0; i < gl.gl_pathc; i++) {
		dbg("Including file %s ...", gl.gl_pathv[i]);
		if (config_parse(gl.gl_pathv[i]))
		    warning("failed including %s", gl.gl_pathv[i]);
	    }
	    globfree(&gl);
	}
	| NO PHYINT		{ config_set_ifflag(IFIF_DISABLED); }
	| PHYINT STRING
	{
	    ifi = config_iface_add($2);
	    if (!ifi)
		ifi = &scrap;
	    twin = ifi == &scrap ? NULL : config_iface_twin(ifi);
	    off4 = off6 = 0;
	}
	ifmods
	{
	    if (off6 && twin)
		config_iface_del(twin);
	    if (off4 && ifi != &scrap)
		config_iface_del(ifi);
	    ifi = &scrap;
	    twin = NULL;
	}
	| NO ROUTER_ALERT
	{
	    router_alert = 0;
	}
	| ROUTER_ALERT BOOLEAN
	{
	    router_alert = $2;
	}
	| ROUTER_TIMEOUT NUMBER
	{
	    if ($2 < 1 || $2 > 1024)
		fatal("Invalid multicast router timeout [1,1024]: %d", $2);
	    router_timeout = $2;
	}
	| GLOBAL_QUERY_INTERVAL NUMBER
	{
	    if ($2 < 1 || $2 > 1024)
		fatal("Invalid multicast query interval [1,1024]: %d", $2);
	    igmp_query_interval = $2;
	}
	| GLOBAL_QUERY_RESPONSE_INTERVAL NUMBER
	{
	    if ($2 < 1 || $2 > 1024)
		fatal("Invalid multicast query response interval [1,1024]: %d", $2);
	    igmp_response_interval = $2;
	}
	| GLOBAL_QUERY_LAST_MEMBER_INTERVAL NUMBER
	{
	    if ($2 < 1 || $2 > 1024)
		fatal("Invalid multicast query interval [1,1024]: %d", $2);
	    igmp_last_member_interval = $2;
	}
	| IGMP_ROBUSTNESS NUMBER
	{
	    if ($2 < 2 || $2 > 10)
		fatal("Invalid multicast robustness value [2,10]: %d", $2);
	    igmp_robustness = $2;
	}
	;

ifmods	: /* empty */
	| ifmods ifmod
	;

ifmod	: DISABLE		{ ifset(IFIF_DISABLED, 0); }
	| ENABLE		{ ifset(0, IFIF_DISABLED); }
	| PROXY_QUERIER		{ ifset(IFIF_PROXY_QUERIER, 0); }
	| IGMPV1		{ ifi->ifi_compat = GEN_V1; }
	| IGMPV2		{ ifi->ifi_compat = GEN_V2; }
	| IGMPV3		{ ifi->ifi_compat = GEN_V3; }
	| MLDV1		{ if (twin) twin->ifi_compat = GEN_V2; }
	| MLDV2		{ if (twin) twin->ifi_compat = GEN_V3; }
	| IGMP BOOLEAN	{ off4 = !$2; }
	| MLD BOOLEAN	{ off6 = !$2; }
	| STATIC_GROUP GROUP
	{
	    struct listaddr *a;

	    a = calloc(1, sizeof(struct listaddr));
	    if (!a) {
		fatal("Failed allocating memory for 'struct listaddr'");
		return 0;
	    }

	    a->al_addr  = $2;
	    a->al_pv    = 2;	/* IGMPv2 only, no SSM */
	    a->al_flags = NBRF_STATIC_GROUP;
	    time(&a->al_ctime);

	    if (a->al_addr.family == AF_INET6 && twin)
		TAILQ_INSERT_TAIL(&twin->ifi_static, a, al_link);
	    else
		TAILQ_INSERT_TAIL(&ifi->ifi_static, a, al_link);
	}
	| QUERY_INTERVAL NUMBER
	{
	    if ($2 < 1 || $2 > 1024)
		fatal("Invalid multicast query interval [1,1024]: %d", $2);
	    ifi->ifi_query_interval = $2;
	    if (twin)
		twin->ifi_query_interval = $2;
	}
	| VLAN NUMBER
	{
	    if ($2 < 1 || $2 > 4094)
		fatal("Invalid VLAN ID [1,4094]");
	    ifi = config_iface_vlan(ifi, $2);
	    twin = config_iface_twin(ifi);
	}
	;

%%

static void fatal(const char *fmt, ...)
{
    char buf[MAXHOSTNAMELEN + 100];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    errx("%s:%d: %s", config_file, lineno, buf);
    exit(EX_DATAERR);
}

static void warning(const char *fmt, ...)
{
    char buf[200];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    warnx("%s:%d: %s", config_file, lineno, buf);
}

static void yyerror(char *msg)
{
    errx("%s:%d: %s", config_file, lineno, msg);
    exit(EX_DATAERR);
}

static char *yytoken(void)
{
    static char buf[1024];
    static char *p = NULL;
    char *q;

    while (1) {
        if (!p || !*p) {
            lineno++;
            if (fgets(buf, sizeof(buf), yyin) == NULL)
                return NULL;
            p = buf;
        }

        while (*p && (*p == ' ' || *p == '\t'))	/* skip whitespace */
            p++;

        if (*p == '#') {
            p = NULL;		/* skip comments */
            continue;
        }

        q = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n')
            p++;		/* find next whitespace */
        if (*p)		/* not at the end of buf */
            *p++ = '\0';	/* null-terminate string */

        if (!*q) {
            p = NULL;
            continue;	/* if 0-length string, read another line */
        }

        return q;
    }
}

/*
 * List of keywords.  Must have an empty record at the end to terminate
 * list.  If a second value is specified, the first is used at the beginning
 * of the file and the second is used while parsing interfaces (e.g. after
 * the first "phyint" or "tunnel" keyword).
 */
static struct keyword {
	char	*word;
	int	val1;
	int	val2;
} words[] = {
	{ "global-query-interval",       GLOBAL_QUERY_INTERVAL, 0 },
	{ "global-response-interval",    GLOBAL_QUERY_RESPONSE_INTERVAL, 0 },
	{ "global-last-member-interval", GLOBAL_QUERY_LAST_MEMBER_INTERVAL, 0 },
	{ "query-interval",     QUERY_INTERVAL, 0 },
	{ "robustness",         IGMP_ROBUSTNESS, 0 },
	{ "router-timeout",     ROUTER_TIMEOUT, 0 },
	{ "include",            INCLUDE, 0 },
	{ "no",                 NO, 0 },
	{ "phyint",		PHYINT, 0 },
	{ "iface",		PHYINT, 0 },
	{ "vlan",		VLAN, 0 },
	{ "disable",		DISABLE, 0 },
	{ "enable",		ENABLE, 0 },
	{ "router-alert",	ROUTER_ALERT, 0 },
	{ "igmpv1",		IGMPV1, 0 },
	{ "igmpv2",		IGMPV2, 0 },
	{ "igmpv3",		IGMPV3, 0 },
	{ "mldv1",		MLDV1, 0 },
	{ "mldv2",		MLDV2, 0 },
	{ "igmp",		IGMP, 0 },
	{ "mld",		MLD, 0 },
	{ "static-group",	STATIC_GROUP, 0 },
	{ "proxy-queries",	PROXY_QUERIER, 0}, /* compat */
	{ "proxy-mode",		PROXY_QUERIER, 0},
	{ NULL,			0, 0 }
};


static int yylex(void)
{
    struct keyword *w;
    uint32_t addr, n;
    struct in6_addr in6;
    char dq[INET_ADDRSTRLEN];
    char *q;

    q = yytoken();
    if (!q)
        return 0;

    for (w = words; w->word; w++) {
        if (!strcmp(q, w->word))
            return w->val2 ? w->val2 : w->val1;
    }

    if (!strcmp(q, "on") || !strcmp(q, "yes")) {
        yylval.num = 1;
        return BOOLEAN;
    }

    if (!strcmp(q, "off") || !strcmp(q, "no")) {
        yylval.num = 0;
        return BOOLEAN;
    }

    if (inet_pton(AF_INET6, q, &in6) == 1) {
	inet_addr_set6(&yylval.ina, &in6);
	if (inet_addr_is_group(&yylval.ina))
	    return GROUP;
    }

    /* dq holds "255.255.255.255" at most; longer is no address anyway */
    if (sscanf(q, "%15[.0-9]/%u%c", dq, &n, s2) == 2) {
	addr = inet_parse(dq, 1);
        /* fall through to returning STRING */
    } else if (sscanf(q, "%15[.0-9]%c", dq, s2) == 1) {
	addr = inet_parse(dq, 4);
        if (addr != 0xffffffff) {
	    if (inet_valid_host(addr)) {
		yylval.addr = addr;
		return ADDR;
	    }
	    if (inet_valid_group(addr)) {
		inet_addr_set4(&yylval.ina, addr);
		return GROUP;
	    }
        }
    }

    if (sscanf(q, "0x%8x%c", &n, s1) == 1) {
        yylval.addr = n;
        return ADDR;
    }

    if (sscanf(q, "%u%c", &n, s1) == 1) {
        yylval.num = n;
        return NUMBER;
    }

    yylval.ptr = q;

    return STRING;
}

void config_init(void)
{
    TAILQ_INIT(&scrap.ifi_static);
    TAILQ_INIT(&scrap.ifi_groups);

    lineno = 0;

    dbg("Parsing file %s ...", config_file);
    if (config_parse(config_file) && errno != ENOENT) {
	err("cannot open %s", config_file);
	exit(EX_DATAERR);
    }

    /* Unless set, follows the intervals and robustness just read */
    if (!router_timeout)
	router_timeout = IGMP_OTHER_QUERIER_PRESENT_INTERVAL;
}

int config_parse(const char *file)
{
    FILE *fp, *oldfp;

    fp = fopen(file, "r");
    if (!fp)
	return -1;

    oldfp = yyin;
    yyin = fp;
    yyparse();
    fclose(fp);
    yyin = oldfp;

    return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
