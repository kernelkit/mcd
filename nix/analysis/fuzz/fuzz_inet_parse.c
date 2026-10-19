/*
 * libFuzzer harness for inet_parse() (src/inet.c), the dotted-quad parser
 * the config lexer uses for addresses and prefixes, plus the formatting
 * helpers its results go through.
 *
 * Input: byte 0 picks the number of octets inet_parse() requires (1..4);
 * the rest, NUL-terminated, is the string.
 *
 * SPDX-License-Identifier: ISC
 */

#include "defs.h"

#include "fuzz_harness.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char out[INET_ADDRSTR_LEN];
	uint32_t addr;
	char *s;
	int n;

	if (size < 1)
		return 0;

	n = (data[0] & 3) + 1;
	s = malloc(size);
	if (!s)
		abort();
	memcpy(s, data + 1, size - 1);
	s[size - 1] = '\0';

	addr = inet_parse(s, n);
	if (addr != 0xffffffff) {
		inet_fmt(addr, out, sizeof(out));
		(void)inet_valid_host(addr);
		(void)inet_valid_group(addr);
	}

	free(s);
	return 0;
}
