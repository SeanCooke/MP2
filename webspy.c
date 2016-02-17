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

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "webspy.h"

/*
 * Function Prototypes
 */
extern pcap_t * init_pcap (FILE * thefile, char * filename);
extern void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

int
usage (void)
{
	fprintf (stderr, "prpacket <tcpdump file>\n");
	return 0;
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
int
main (int argc, char ** argv)
{
	/* The libpcap descriptor */
	pcap_t * pcapd;

	/* The buffer that we have libpcap use for packet capture */
	static unsigned char buffer [MAX_SNAPLEN];

	/*
	 * Determine if the command line arguments are valid.
	 */
	if (argc != 2)
	{
		fprintf (stderr, "%s: Invalid number of arguments\n", argv[0]);
		usage ();
		exit (1);
	}

	/*
	 * Initialize the libpcap functions.  We will be relying on tcpdump
	 * to filter out unwanted connections, so we'll be reading from a file
	 * of some sort.
	 */
	if ((pcapd = init_pcap (stdout, argv[1])) == NULL)
	{
		fprintf (stderr, "%s: Failed to initialize pcap\n", argv[0]);
		exit (1);
	}

	/*
	 * Begin looping through collecting packets until we hit the
	 * end of the file.
	 */
	if ((pcap_loop (pcapd, 0, process_packet, buffer)) == -1)
	{
		pcap_perror (pcapd, argv[0]);
	}

	/*
	 * Exit with no errors
	 */
	exit (0);
}
