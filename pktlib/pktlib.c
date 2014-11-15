#include "pktlib.h"
#include "protocol.h"

int pktlib_init(struct packet_parser *parser, allocator_func allocator, void *cookie)
{
	if (!allocator)
		return -1;

	parser->alloc = allocator;
	parser->cookie = cookie;
	return 0;
}

struct packet *pktlib_process(struct packet_parser *parser, const uint8_t *data, size_t len)
{
	struct packet *pkt = proto_eth_parse(parser, data, len, 0);
	if (!pkt)
		goto out;

	pkt->len = len;
out:
	return pkt;
}

