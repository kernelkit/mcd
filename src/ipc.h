/*
 * Copyright (c) 2018-2020  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
