#include <string.h>
#include <arpa/inet.h>
#include "protocol.h"

/* Ethernet protocol support */
struct packet *proto_hdr_none(struct packet_parser *parser, size_t offset)
{
	struct packet * pkt = parser->alloc(sizeof(*pkt) + offset +
					    sizeof(struct header),
					    parser->cookie);
	if (!pkt)
		goto out;

	struct header *hdr = (struct header *)((uint8_t *)(pkt + 1) + offset);
	hdr->type = HDR_NONE;

out:
	return pkt;
}

struct packet *proto_eth_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset)
{
	if (len < sizeof(struct eth_hdr))
		goto unknown_header;

	struct eth_hdr *ethh = (struct eth_hdr *)data;
	uint16_t proto = ntohs(ethh->proto);
	if (proto < ETH_TYPE_LIMIT)
		goto unknown_header;

	/* TODO: parse next protocols */
	struct packet *pkt = proto_hdr_none(parser, offset + pktlib_pkt_hdr_size(HDR_ETH));
	if (!pkt)
		return NULL;

	struct header *hdr = pktlib_pkt_get_hdr(pkt, offset);
	hdr->type = HDR_ETH;

	struct header_eth *eth_info = (struct header_eth *)hdr->header_info;
	memcpy(eth_info->source, ethh->source, ETH_ADDR_LEN);
	memcpy(eth_info->dest, ethh->dest, ETH_ADDR_LEN);
	eth_info->proto = proto;
	return pkt;

unknown_header:
	/* no recognized header in the packet;
	 * return a packet with a "no header" */
	return proto_hdr_none(parser, offset);
}
