#include <inttypes.h>
#include "pktlib.h"

/* Ethernet II */
#define ETH_ADDR_LEN	(6)
#define ETH_TYPE_LIMIT	1536

struct eth_hdr {
	uint8_t dest[ETH_ADDR_LEN];
	uint8_t source[ETH_ADDR_LEN];
	uint16_t proto;
} __attribute__((packed));

typedef int (*header_parser_func)(const uint8_t *, size_t, struct header *);

struct packet *proto_eth_parse(struct packet_parser *parser, const uint8_t *data, size_t len, size_t offset);

void proto_init(void);
