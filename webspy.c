/*
 * Webspy
 *
 * AUTHOR:	You!
 *
 * FILE:	webspy.c
 *
 * PURPOSE:	This file contains the functions that start up the webspy
 *		program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "httpfilter.h"
#include "webspy.h"

#define SIZE_ETHERNET 14

/*
 * Function Prototypes
 */
extern pcap_t * init_pcap(FILE * thefile, char * filename);
void packet_captured(u_char * thing, const struct pcap_pkthdr * packet_header,
		const u_char * packet);
void print_packet(FILE * outfile, const unsigned char ** packet);
FILE * outfile;

int usage(void) {
	fprintf(stderr, "prpacket <tcpdump file>\n");
	return 0;
}

void print_packet(FILE * outfile, const unsigned char ** packet) {
	struct ether_header header;
	struct ip ip_header;
	struct tcphdr tcp_header;
	int index;
	int size_ip;
	int size_tcp;
	int size_payload;
	int ip_len;
	const unsigned char * p_start = *packet;

	/*
	 * Align the data by copying it into a Ethernet header structure.
	 */
	bcopy(*packet, &header, sizeof(struct ether_header));

	/*
	 * Print out the Ethernet information.
	 */
	/*fprintf(outfile, "================= ETHERNET HEADER ==============\n");
	fprintf(outfile, "Source Address:\t\t");
	for (index = 0; index < ETHER_ADDR_LEN; index++) {
		fprintf(outfile, "%x", header.ether_shost[index]);
	}
	fprintf(outfile, "\n");

	fprintf(outfile, "Destination Address:\t");
	for (index = 0; index < ETHER_ADDR_LEN; index++) {
		fprintf(outfile, "%x", header.ether_dhost[index]);
	}
	fprintf(outfile, "\n");

	fprintf(outfile, "Protocol Type:\t\t");
	switch (ntohs(header.ether_type)) {
	case ETHERTYPE_PUP:
		fprintf(outfile, "PUP Protocol\n");
		break;

	case ETHERTYPE_IP:
		fprintf(outfile, "IP Protocol\n");
		break;

	case ETHERTYPE_ARP:
		fprintf(outfile, "ARP Protocol\n");
		break;

	case ETHERTYPE_REVARP:
		fprintf(outfile, "RARP Protocol\n");
		break;

	default:
		fprintf(outfile, "Unknown Protocol: %x\n", header.ether_type);
		break;
	}*/

	/*
	 * Adjust the pointer to point after the Ethernet header.
	 */
	*packet += sizeof(struct ether_header);

	bcopy(*packet, &ip_header, sizeof(struct ip));

	/*fprintf(outfile, "================= IP HEADER ==============\n");
	fprintf(outfile, "Source Address:\t\t");

	fprintf(outfile, "%s", inet_ntoa(ip_header.ip_src));

	fprintf(outfile, "\n");

	fprintf(outfile, "Destination Address:\t");

	fprintf(outfile, "%s", inet_ntoa(ip_header.ip_dst));

	fprintf(outfile, "\n");*/
	size_ip = (ip_header.ip_hl) * 4;
	ip_len = ntohs(ip_header.ip_len);

	/*
	 * Adjust the pointer to point after the IP header.
	 */
	*packet += sizeof(struct ip);

	const char *payload;

	bcopy(*packet, &tcp_header, sizeof(struct tcphdr));

	/*fprintf(outfile, "================= TCP HEADER ==============\n");
	fprintf(outfile, "Source Port:\t\t");

	fprintf(outfile, "%d", ntohs(tcp_header.th_sport));

	fprintf(outfile, "\n");

	fprintf(outfile, "Destination Port:\t");

	fprintf(outfile, "%d", ntohs(tcp_header.th_dport));

	fprintf(outfile, "\n");*/
	size_tcp = (tcp_header.th_off) * 4;

	/*
	 * Adjust the pointer to point after the TCP header.
	 */
	*packet += sizeof(struct tcphdr);

	size_payload = ip_len - (size_ip + size_tcp);

	//printf("   Payload (%d bytes):\n", size_payload);

	payload = (u_char *) (p_start + SIZE_ETHERNET + size_ip + size_tcp);

	if (size_payload > 0) {
		if (strncmp(payload, "GET", strlen("GET")) == 0
				|| strncmp(payload, "POST", strlen("POST")) == 0) {
			char httpHdrStr[size_payload];
			for (int i = 0; i < size_payload; i++) {
				if (isprint(*payload)){
					//printf("%c", *payload);
					httpHdrStr[i] = *payload;
				}
				else{
					//printf("\n");
					httpHdrStr[i] = '\n';
				}
				payload++;
			}
			char * token, * host, * path;
			token = strtok(httpHdrStr, "\n\n");
			char *httpHdr[sizeof(strtok(httpHdrStr, "\n\n"))];
			httpHdr[0] = token;
			int i = 0;
			while (token != NULL) {
				httpHdr[i] = token;
				token = strtok(NULL, "\n\n");
				i++;
			}
			host = strtok(httpHdr[1], " ");
			host = strtok(NULL, " ");
			path = strtok(httpHdr[0], " ");
			path = strtok(NULL, " ");
			if(ntohs(tcp_header.th_dport) == 80){
				printf("http://");
			}else if(ntohs(tcp_header.th_dport) == 443){
				printf("https://");
			}
			printf(host); printf(path);
			printf("\n");
		}
	}

	/*
	 * Return indicating no errors.
	 */
	return;
}

void packet_captured(u_char * thing, const struct pcap_pkthdr * packet_header,
		const u_char * packet) {
	/* Determine where the IP Header is */
	const unsigned char * pointer;

	/* Length of the data */
	long packet_length;

	/*
	 * Filter the packet using our BPF filter.
	 */
	if ((pcap_offline_filter(&HTTPFilter, packet_header, packet) == 0)) {
		return;
	}

	/*
	 * Print the Ethernet Header
	 */
	pointer = packet;
	print_packet(outfile, &pointer);

	return;
}

/*
 * Function: main ()
 *
 * Purpose:
 *	This function will interpret the command line arguments and get
 *	things started.
 *
 * Inputs values:
 *	argc - The number of command line arguments.
 *	argv - The command line arguments.
 */
int main(int argc, char ** argv) {
	/* The libpcap descriptor */
	pcap_t * pcapd;

	/* The buffer that we have libpcap use for packet capture */
	static unsigned char buffer[MAX_SNAPLEN];

	/*
	 * Determine if the command line arguments are valid.
	 */
	if (argc != 2) {
		fprintf(stderr, "%s: Invalid number of arguments\n", argv[0]);
		usage();
		exit(1);
	}

	/*
	 * Initialize the libpcap functions.  We will be relying on tcpdump
	 * to filter out unwanted connections, so we'll be reading from a file
	 * of some sort.
	 */
	if ((pcapd = init_pcap(stdout, argv[1])) == NULL) {
		fprintf(stderr, "%s: Failed to initialize pcap\n", argv[0]);
		exit(1);
	}

	/*if (pcap_setfilter(pcapd, &HTTPFilter) == -1) {
		fprintf(stderr, "cannot set pcap filter\n");
		exit(1);
	}*/

	/*
	 * Begin looping through collecting packets until we hit the
	 * end of the file.
	 */
	if ((pcap_loop(pcapd, -1, packet_captured, buffer)) == -1) {
		pcap_perror(pcapd, argv[0]);
	}

	/*
	 * Exit with no errors
	 */
	exit(0);
}
