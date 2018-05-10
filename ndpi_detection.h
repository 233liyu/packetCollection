//
// Created by lee yu on 2018/4/24.
//

#ifndef LIBPCAP_NDPI_DETECTION_H
#define LIBPCAP_NDPI_DETECTION_H

#endif //LIBPCAP_NDPI_DETECTION_H



struct ndpi_packet{
	// initial packet from libpcap
	char * ip_packet;
	// ip header offset from the packet
	int iphd_offset;
	// payload offset from the packet header
	int payload_offset;
	// ipv4 / ipv6
	int ip_version;
	// TCP / UDP
	int protocol;
	// session key
	char * session_key;
	int payload_length;

	struct ndpi_packet * next_node;
};

void run_ndpi_detection(char * ip_packet, int iphd_offset, int payload_offset,
						int ip_version, int protocol, char * session_key, int payload_length);