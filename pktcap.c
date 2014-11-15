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

int pktcap_process(int sockfd)
{
	ssize_t len;
	uint8_t pkt[65536];

	len = read(sockfd, pkt, sizeof(pkt));
	if (len < 0) {
		perror("read():");
	} else if (len == 0) {
		printf("[DONE]\n");
		exit(0);
	} else {
		printf("Frame [len = %zi]\n", len);
	}

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

	while (1) {
		pktcap_process(sockfd);
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
