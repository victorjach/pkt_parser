#include <inttypes.h>
#include "pktlib.h"

/* Ethernet II */
#define ETH_ADDR_LEN	(6)
#define ETH_TYPE_LIMIT	1536

/* Eth proto types */
#define ETH_PROTO_ARP	0x0806
#define ETH_PROTO_IP	0x0800

struct eth_hdr {
	uint8_t dest[ETH_ADDR_LEN];
	uint8_t source[ETH_ADDR_LEN];
	uint16_t proto;
} __attribute__((packed));

typedef int (*header_parser_func)(const uint8_t *, size_t, struct header *);

struct packet *proto_eth_parse(struct packet_parser *parser, const uint8_t *data, size_t len, size_t offset);

/* ARP support */
struct arp_hdr {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_addr_len;
	uint8_t proto_addr_len;
	uint16_t opcode;
	uint8_t data[0];
};

struct packet *proto_arp_parse(struct packet_parser *parser, const uint8_t *data, size_t len, size_t offset);

/* IPv4 support */
struct ip_hdr {
#if defined(__BIG_ENDIAN)
	uint8_t ihl:4;
	uint8_t version:4;
#elif defined (__LITTLE_ENDIAN)
	uint8_t version:4;
	uint8_t ihl:4;
#else
#error "Please define byteorder"
#endif
	union {
		uint8_t	tos;
		struct {
#if defined(__BIG_ENDIAN)
			uint8_t ecn:2;
			uint8_t dscp:6;
#elif defined (__LITTLE_ENDIAN)
			uint8_t dscp:6;
			uint8_t ecn:2;
#endif
		};
	};

	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t check;
	uint32_t source;
	uint32_t dest;
} __attribute__((packed));

#define IP_PROTOCOL_ICMP 0x01
#define IP_PROTOCOL_IPIP 0x04
#define IP_PROTOCOL_UDP 0x11

struct packet *proto_ip_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset);

/* ICMP support */
struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t check;
	union {
		uint32_t unused;
		struct {
#if defined(__BIG_ENDIAN)
			uint32_t unused_1:24;
			uint32_t pointer:8;
#elif defined (__LITTLE_ENDIAN)
			uint32_t unused_1:24;
			uint32_t pointer:8;
#endif
		};
		uint32_t gateway_addr;

		struct {
			uint16_t id;
			uint16_t seqno;
		};
	};

	uint8_t data[0];
} __attribute__((packed));

struct icmp_timestamp {
	uint32_t orig_timestamp;
	uint32_t recv_timestamp;
	uint32_t trans_timestap;
};

struct packet *proto_icmp_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset);

/* UDP support */
struct udp_hdr {
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

struct packet *proto_udp_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset);

void proto_init(void);
