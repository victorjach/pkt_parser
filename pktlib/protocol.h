#include <inttypes.h>
#include "pktlib.h"

/* Ethernet II */
#define ETH_ADDR_LEN	(6)
#define ETH_TYPE_LIMIT	1536

/* Eth proto types */
#define ETH_PROTO_ARP	0x0806

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

void proto_init(void);
