#include "pktlib.h"

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
	return NULL;
}

