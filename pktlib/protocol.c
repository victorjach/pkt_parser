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

	size_t new_offset = offset + pktlib_pkt_hdr_size(HDR_ETH);
	len -= sizeof(struct eth_hdr);
	data += sizeof(struct eth_hdr);

	struct packet *pkt;
	switch (proto) {
	case ETH_PROTO_ARP:
		pkt = proto_arp_parse(parser, data, len, new_offset);
		break;
	case ETH_PROTO_IP:
		pkt = proto_ip_parse(parser, data, len, new_offset);
		break;
	default:
		pkt = proto_hdr_none(parser, new_offset);
		break;
	}

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

/* ARP support */
struct packet *proto_arp_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset)
{
	if (len < sizeof(struct arp_hdr))
		goto unknown_header;

	struct arp_hdr *arph = (struct arp_hdr *)data;
	size_t aux_size = 2 * (arph->hw_addr_len + arph->proto_addr_len);
	struct packet *pkt = proto_hdr_none(parser, offset + pktlib_pkt_hdr_size(HDR_ARP) + aux_size);
	if (!pkt)
		return NULL;

	struct header *hdr = pktlib_pkt_get_hdr(pkt, offset);
	hdr->type = HDR_ARP;

	struct header_arp *arp_info = (struct header_arp *)hdr->header_info;
	memset(arp_info, 0, sizeof(*arp_info));
	arp_info->hw_type = ntohs(arph->hw_type);
	arp_info->proto_type = ntohs(arph->proto_type);
	arp_info->hw_addr_len = arph->hw_addr_len;
	arp_info->proto_addr_len = arph->proto_addr_len;
	arp_info->opcode = ntohs(arph->opcode);

	/* ARP header incomplete ?! */
	if (len < sizeof(struct arp_hdr) + aux_size)
		return pkt;

	/* copy variable length addreses */
	uint8_t *arph_ptr = &arph->data[0];
	uint8_t *arp_info_ptr = &arp_info->data[0];
	arp_info->hw_addr_sender = arp_info_ptr;
	memcpy(arp_info_ptr, arph_ptr, arp_info->hw_addr_len);
	arp_info_ptr += arp_info->hw_addr_len;
	arph_ptr += arp_info->hw_addr_len;

	arp_info->proto_addr_sender = arp_info_ptr;
	memcpy(arp_info_ptr, arph_ptr, arp_info->proto_addr_len);
	arp_info_ptr += arp_info->proto_addr_len;
	arph_ptr += arp_info->proto_addr_len;

	arp_info->hw_addr_target = arp_info_ptr;
	memcpy(arp_info_ptr, arph_ptr, arp_info->hw_addr_len);
	arp_info_ptr += arp_info->hw_addr_len;
	arph_ptr += arp_info->hw_addr_len;

	arp_info->proto_addr_target = arp_info_ptr;
	memcpy(arp_info_ptr, arph_ptr, arp_info->proto_addr_len);

	return pkt;

unknown_header:
	/* no recognized header in the packet;
	 * return a packet with a "no header" */
	return proto_hdr_none(parser, offset);
}

/* IPv4 support */
static void copy_ip_info(struct header_ip *ip_info, struct ip_hdr *iph)
{
	memset(ip_info, 0, sizeof(*ip_info));
	ip_info->version = iph->version;
	ip_info->header_len = iph->ihl * 4;
	ip_info->dscp = iph->dscp;
	ip_info->ecn = iph->ecn;
	ip_info->tos = iph->tos;
	ip_info->total_len = ntohs(iph->tot_len);
	ip_info->id = ntohs(iph->id);
	uint16_t frag_off = ntohs(iph->frag_off);
	ip_info->frag_offset = frag_off & ((1 << 13) - 1);
	ip_info->flags = frag_off >> 13;
	ip_info->ttl = iph->ttl;
	ip_info->proto = iph->proto;
	ip_info->checksum = ntohs(iph->check);
	/* TODO: validate checksum */
	ip_info->source = iph->source;
	ip_info->dest = iph->dest;
	/* TODO: IP options */
}

struct packet *proto_ip_parse(struct packet_parser *parser, const uint8_t *data,
			      size_t len, size_t offset)
{
	if (len < sizeof(struct ip_hdr))
		goto unknown_header;

	struct ip_hdr *iph = (struct ip_hdr *)data;
	size_t aux_size = iph->ihl * 4;
	aux_size = aux_size > sizeof(struct ip_hdr) ? aux_size - sizeof(struct ip_hdr) : 0;

	if (iph->version != 4)
		goto unknown_header;

	/* TODO: add support for L4 headers */
	struct packet *pkt = proto_hdr_none(parser, offset + pktlib_pkt_hdr_size(HDR_IP) + aux_size);
	if (!pkt)
		return NULL;

	struct header *hdr = pktlib_pkt_get_hdr(pkt, offset);
	hdr->type = HDR_IP;
	struct header_ip *ip_info = (struct header_ip *)hdr->header_info;
	copy_ip_info(ip_info, iph);

	return pkt;

unknown_header:
	/* no recognized header in the packet;
	 * return a packet with a "no header" */
	return proto_hdr_none(parser, offset);
}


