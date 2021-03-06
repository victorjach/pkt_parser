#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include "pktlib.h"

void print_eth_packet(struct header_eth *ethh)
{
	printf("\t[Ethernet II]\n");
	printf("\t\tSource address:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
	       ethh->source[0], ethh->source[1], ethh->source[2],
	       ethh->source[3], ethh->source[4], ethh->source[5]);
	printf("\t\tDestination address:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
	       ethh->dest[0], ethh->dest[1], ethh->dest[2],
	       ethh->dest[3], ethh->dest[4], ethh->dest[5]);
	printf("\t\tProtocol: 0x%X\n", ethh->proto);
}

void print_vlan_packet(struct header_vlan *vlanh)
{
	printf("\t[802.1Q]\n");
	printf("\t\tVLAN: %u\n", vlanh->vid);
}

void print_arp_packet(struct header_arp *arph)
{
	printf("\t[ARP]\n");
	printf("\t\tHardware type: ");
	if (arph->hw_type == 0x0001)
		printf("Ethernet(0x%X)\n", arph->hw_type);
	else
		printf("Unknown(0x%X)\n", arph->hw_type);

	printf("\t\tProtocol type: ");
	if (arph->proto_type == 0x0800)
		printf("IPv4(0x%X)\n", arph->proto_type);
	else
		printf("Unknown(0x%x)\n", arph->proto_type);


	printf("\t\tHW address len: %u\n", arph->hw_addr_len);
	printf("\t\tProto address len: %u\n", arph->proto_addr_len);

	printf("\t\tOpcode: ");
	switch (arph->opcode) {
	case 0x0001:
		printf("request");
		break;
	case 0x0002:
		printf("response");
		break;
	default:
		printf("unknown");
		break;
	}

	printf(" (0x%X)\n", arph->opcode);
	/* TODO: print addresses */
}

void print_ip_packet(struct header_ip *ip)
{
	void print_ip_addr(uint32_t addr)
	{
		uint8_t *ip = (uint8_t *)&addr;
		printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	}

	printf("\t[IPv4]\n");
	printf("\t\tHeader length: %u\n", ip->header_len);
	printf("\t\tTOS: DSCP(0x%02X) ECN(0x%02X)\n", ip->dscp, ip->ecn);
	printf("\t\tTotal length: %u\n", ip->total_len);
	printf("\t\tIdentification: 0x%04X\n", ip->id);
	printf("\t\tFlags: 0x%02X\n", ip->flags);
	printf("\t\tFragment offset: 0x%04X\n", ip->frag_offset);
	printf("\t\tTTL: %u\n", ip->ttl);

	printf("\t\tProtocol: ");
	switch(ip->proto) {
	case 0x06:
		printf("TCP");
		break;
	case 0x11:
		printf("UDP");
		break;
	case 0x01:
		printf("ICMP");
		break;
	default:
		printf("Unknown");
	}

	printf("(0x%X)\n", ip->proto);

	printf("\t\tSource: ");
	print_ip_addr(ip->source);
	printf("\n");

	printf("\t\tDestination: ");
	print_ip_addr(ip->dest);
	printf("\n");
}

void print_icmp_packet(struct header_icmp *icmp)
{
	printf("\t[ICMP]\n");
	printf("\t\tType: ");
	switch (icmp->type) {
	case 3:
		printf("Destination unreachable\n");

		break;
	case 11:
		printf("Time exceeded\n");
		break;
	case 12:
		printf("Parameter problem\n");
		break;
	case 4:
		printf("Source quench\n");
		break;
	case 5:
		printf("Redirect\n");
		break;
	case 0:
		printf("Echo request\n");
		printf("\t\tId: %02X\n", icmp->id);
		printf("\t\tSequence number: 0x%02X\n", icmp->seqno);
		break;
	case 8:
		printf("Echo reply\n");
		printf("\t\tId: %02X\n", icmp->id);
		printf("\t\tSequence number: 0x%02X\n", icmp->seqno);
		break;
	case 13:
		printf("Timestamp\n");
		break;
	case 14:
		printf("Timestamp reply\n");
		break;
	case 15:
		printf("Info request\n");
		break;
	case 16:
		printf("Info reply\n");
		break;
	default:
		printf("Unknown(%02X)\n", icmp->type);
	}

	printf("\t\tCode: %04X\n", icmp->code);
	/* TODO: print ip header for other type as well */
	if (icmp->type == 0x03) {
		print_ip_packet(&icmp->ip);
	}
}

void print_udp_packet(struct header_udp *udp)
{
	printf("\t[UDP]\n");
	printf("\t\tSource port: %u\n", udp->source_port);
	printf("\t\tDestination port: %u\n", udp->dest_port);
	printf("\t\tLength: %u\n", udp->length);
}

void print_tcp_packet(struct header_tcp *tcp)
{
	printf("\t[TCP]\n");
	printf("\t\tSource port: %u\n", tcp->source_port);
	printf("\t\tDestination port: %u\n", tcp->dest_port);
	printf("\t\tSequence number: %u\n", tcp->seqno);
	printf("\t\tAcknoledgment number: %u\n", tcp->ackno);

	printf("\t\tFlags: ");
	if (tcp->syn)
		printf("syn ");
	if (tcp->fin)
		printf("fin ");
	if (tcp->rst)
		printf("rst ");
	if (tcp->psh)
		printf("psh ");
	if (tcp->ack)
		printf("ack ");
	if (tcp->urg)
		printf("urg ");
	if (tcp->ece)
		printf("ece ");
	if (tcp->cwr)
		printf("cwr ");
	if (tcp->ns)
		printf("ns ");

	printf("\n");
	printf("\t\tHeader length: %u\n", tcp->header_len);
	printf("\t\tSegment length: %u\n", tcp->segment_len);
}

void print_packet(struct packet *pkt)
{
	printf("[Frame, len=%zu]\n", pkt->len);

	struct header *hdr;

	pktlib_pkt_for_each(hdr, pkt) {
		switch (hdr->type) {
		case HDR_ETH:
			print_eth_packet((struct header_eth *)hdr->header_info);
			break;
		case HDR_VLAN:
			print_vlan_packet((struct header_vlan *)hdr->header_info);
			break;
		case HDR_ARP:
			print_arp_packet((struct header_arp *)hdr->header_info);
			break;
		case HDR_IP:
			print_ip_packet((struct header_ip *)hdr->header_info);
			break;
		case HDR_ICMP:
			print_icmp_packet((struct header_icmp *)hdr->header_info);
			break;
		case HDR_UDP:
			print_udp_packet((struct header_udp *)hdr->header_info);
			break;
		case HDR_TCP:
			print_tcp_packet((struct header_tcp *)hdr->header_info);
			break;
		default:
			printf("\t[Unknown header]\n");
		}
	}
}

int pktcap_process(struct packet_parser *parser, int sockfd)
{
	ssize_t len;
	uint8_t data[65536];

	len = read(sockfd, data, sizeof(data));
	if (len < 0) {
		perror("read():");
	} else if (len == 0) {
		printf("[DONE]\n");
		exit(0);
	}

	struct packet *pkt = pktlib_process(parser, data, (size_t)len);
	if (!pkt) {
		printf("error: allocation failed\n");
		exit(EXIT_FAILURE);
	}

	print_packet(pkt);
	free(pkt);
	return 0;
}

int pktcap_start(const char *ifname)
{
	int rc;
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd < 0) {
		perror("socket():");
		exit(EXIT_FAILURE);
	}

	struct ifreq ifr;
	strncpy ((char *) ifr.ifr_name, ifname, IFNAMSIZ);
	ioctl (sockfd, SIOCGIFINDEX, &ifr);

	struct sockaddr_ll sll;
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = 0;
	rc = bind(sockfd, (struct sockaddr *)&sll, sizeof(sll));
	if (rc < 0) {
		perror("bind():");
		exit(EXIT_FAILURE);
	}

	struct packet_mreq mr;
	memset (&mr, 0, sizeof (mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof (mr));

	void *alloc(size_t size, void *cookie)
	{
		return malloc(size);
	}

	struct packet_parser parser;
	pktlib_init(&parser, alloc, NULL);
	while (1) {
		pktcap_process(&parser, sockfd);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: pktcap <interface name>\n");
		exit(EXIT_FAILURE);
	}

	printf("Packet Monitor started on interface %s\n", argv[1]);
	pktcap_start(argv[1]);
	return 0;
}
