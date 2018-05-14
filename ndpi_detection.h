//
// Created by lee yu on 2018/4/24.
//

#ifndef LIBPCAP_NDPI_DETECTION_H
#define LIBPCAP_NDPI_DETECTION_H

#endif //LIBPCAP_NDPI_DETECTION_H

#define MAX_EXTRA_PACKETS_TO_CHECK  7


struct ndpi_packet{
	// initial packet from libpcap
	char * packet;
	// ip header size from the packet
	int iphd_size;
	// payload offset from the packet header
	int tu_header_size;
	// ipv4 / ipv6
	int ip_version;
	// TCP / UDP
	int protocol;
	// session key
	char * session_key;

	int payload_length;

	int total_length;
	struct ndpi_packet * next_node;
};

void run_ndpi_detection(char *ip_packet, int iphd_size, int tu_header_size,
						int ip_version, int protocol, char *session_key, int payload_length, int total_length);

void ndpi_workflow_init();

void * process_queue(void *arg);