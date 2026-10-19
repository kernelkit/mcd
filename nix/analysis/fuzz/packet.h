/*
 * Input framing shared by the IGMP and MLD harnesses.
 *
 *   byte 0       mode: FUZZ_MODE_* bits (fuzz_harness.h), the interface
 *                configuration the packets arrive on
 *   then         up to FUZZ_MAX_PACKETS records of
 *                  u16 big-endian length, then that many packet bytes
 *                (IP header onward, as sock_read() passes them). A short
 *                final record takes whatever bytes remain.
 *
 * Several packets per input let the fuzzer drive the querier state
 * machine (report, then leave, then a competing query, ...).
 *
 * SPDX-License-Identifier: ISC
 */

#ifndef FUZZ_PACKET_H
#define FUZZ_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_MAX_PACKETS 8

typedef void (*fuzz_packet_fn)(uint8_t *pkt, size_t len, unsigned int mode, void *ctx);

/* Calls fn once per record, each in its own exact-size heap copy so ASan
 * sees any read past the packet. Returns the mode byte. */
static inline unsigned int fuzz_packets(const uint8_t *data, size_t size, fuzz_packet_fn fn, void *ctx)
{
	unsigned int mode;
	size_t off = 1;

	if (size < 1)
		return 0;
	mode = data[0];

	for (int n = 0; n < FUZZ_MAX_PACKETS && off < size; n++) {
		size_t len;
		uint8_t *pkt;

		if (size - off < 2)
			break;
		len = (size_t)data[off] << 8 | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;

		pkt = malloc(len ? len : 1);
		if (!pkt)
			abort();
		memcpy(pkt, data + off, len);
		fn(pkt, len, mode, ctx);
		free(pkt);
		off += len;
	}

	return mode;
}

#endif /* FUZZ_PACKET_H */
