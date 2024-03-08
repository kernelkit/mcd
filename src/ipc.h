/*
 * Parts of this program has been derived from mrouted.  It is covered
 * by the license in the accompanying file named "LICENSE".
 */
#ifndef MCD_IPC_H_
#define MCD_IPC_H_

#include <stdio.h>

#define TRUEFALSE(v)    (v ? "true" : "false")

extern int detail;
extern int json;
extern int prefix;

static inline void jprint(FILE *fp, const char *key, const char *val, int *first)
{
	fprintf(fp, "%s%*s\"%s\": \"%s\"", *first ? "" : ",\n", prefix, "", key, val);
	*first = 0;
}

static inline void jprintb(FILE *fp, const char *key, int val, int *first)
{
	fprintf(fp, "%s%*s\"%s\": %s", *first ? "" : ",\n", prefix, "", key, TRUEFALSE(val));
	*first = 0;
}
static inline void jprinti(FILE *fp, const char *key, int val, int *first)
{
	fprintf(fp, "%s%*s\"%s\": %d", *first ? "" : ",\n", prefix, "", key, val);
	*first = 0;
}

static inline void jprinta(FILE *fp, const char *key, const char *val, int *first)
{
	fprintf(fp, "%s%*s\"%s\": [ %s ]", *first ? "" : ",\n", prefix, "", key, val);
	*first = 0;
}

#endif /* MCD_IPC_H_ */
