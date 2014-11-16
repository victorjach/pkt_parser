#ifndef __PKTLIB_H__
#define __PKTLIB_H__
#include <stddef.h>
#include <inttypes.h>

enum header_type {
	HDR_ETH,
	HDR_ARP,
	HDR_IP,
	HDR_ICMP,
	HDR_UDP,
	HDR_NONE,
};

struct header {
	enum header_type type;
	uint8_t header_info[0];
};

/* user level headers */
struct header_eth {
	uint8_t source[6];
	uint8_t dest[6];
	uint16_t proto;
};

struct header_arp {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_addr_len;
	uint8_t proto_addr_len;
	uint16_t opcode;
	uint8_t *hw_addr_sender;
	uint8_t *proto_addr_sender;
	uint8_t *hw_addr_target;
	uint8_t *proto_addr_target;
	uint8_t data[0];
};

struct header_ip {
	uint8_t version;
	uint8_t header_len;
	uint8_t dscp;
	uint8_t ecn;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint8_t flags;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	uint32_t source;
	uint32_t dest;
	uint8_t options[0];
};

struct header_icmp {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		uint32_t unused;
		uint32_t gateway;
		uint8_t pointer;
		struct {
			uint16_t id;
			uint16_t seqno;
		};
	};

	struct header_ip ip;
       /* TODO: add member for l4 header */
	union {
		uint8_t data[0];
	};
};

struct header_udp {
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
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
	case HDR_ARP:
		size += sizeof(struct header_arp);
		break;
	case HDR_IP:
		size += sizeof(struct header_ip);
		break;
	case HDR_ICMP:
		size += sizeof(struct header_icmp);
		break;
	case HDR_UDP:
		size += sizeof(struct header_udp);
		break;
	case HDR_NONE:
		break;
	}

	return size;
}

static inline size_t pktlib_pkt_hdr_ext_size(struct header *hdr)
{
	size_t size = 0;

	switch (hdr->type) {
	case HDR_ARP: {
		struct header_arp *arp_info = (struct header_arp *)(hdr + 1);
		size += 2 * (arp_info->hw_addr_len + arp_info->proto_addr_len);
		break;
	}

	default:
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

	return (struct header *)((uint8_t *)hdr + pktlib_pkt_hdr_size(hdr->type) +
				 pktlib_pkt_hdr_ext_size(hdr));
}

#define pktlib_pkt_for_each(hdr, pkt) \
	for (hdr = pktlib_pkt_next_hdr(pkt, NULL); hdr->type != HDR_NONE; hdr = pktlib_pkt_next_hdr(pkt, hdr))

int pktlib_init(struct packet_parser *parser, allocator_func allocator,
		 void *cookie);

struct packet *pktlib_process(struct packet_parser *parser, const uint8_t *data,
			      size_t len);

#endif
