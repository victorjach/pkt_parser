#ifndef __PKTLIB_H__
#define __PKTLIB_H__
#include <stddef.h>
#include <inttypes.h>

enum header_type {
	HDR_ETH,
	HDR_NONE,
};

struct header {
	enum header_type type;
	uint8_t header_info[0];
};

struct header_eth
{
	uint8_t source[14];
	uint8_t dest[14];
	uint16_t proto;
};

struct packet {
	size_t len;
	struct header hdr[0];
};

typedef void *(*allocator_func)(size_t size, void *cookie);

struct packet_parser {
	allocator_func alloc;
	void *cookie;
};

static inline size_t pktlib_pkt_hdr_size(enum header_type type)
{
	size_t size = sizeof(struct header);

	switch (type) {
	case HDR_ETH:
		size += sizeof(struct header_eth);
		break;
	case HDR_NONE:
		break;
	}

	return size;
}

static inline struct header *pktlib_pkt_get_hdr(struct packet *pkt, size_t offset)
{
	return (struct header *)((uint8_t *)pkt->hdr + offset);
}

static inline struct header *pktlib_pkt_next_hdr(struct packet *pkt, struct header *hdr)
{
	if (!hdr)
		return &pkt->hdr[0];

	return (struct header *)((uint8_t *)hdr +
				 pktlib_pkt_hdr_size(hdr->type));
}

#define pktlib_pkt_for_each(hdr, pkt) \
	for (hdr = pktlib_pkt_next_hdr(pkt, NULL); hdr->type != HDR_NONE; hdr = pktlib_pkt_next_hdr(pkt, hdr))

int pktlib_init(struct packet_parser *parser, allocator_func allocator,
		 void *cookie);

struct packet *pktlib_process(struct packet_parser *parser, const uint8_t *data,
			      size_t len);

#endif
