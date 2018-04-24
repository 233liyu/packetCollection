//
// Created by lee yu on 2018/3/22.
//

//

#if defined(__APPLE__)
    #include <ntsid.h>
#endif


#ifndef LIBPCAP_FILE_SYS_H
#define LIBPCAP_FILE_SYS_H

#endif //LIBPCAP_FILE_SYS_H

struct packet_total{
	// "ip.ip.ip.ip:port"
	char * src_add;
	char * dst_add;
    //pay load content
	char * payload;
    // payload size
	int length;
    // TCP / UDP
	int protocol;
    // ipv4 / ipv6
    int ip_version;

	struct packet_total * next_node;
};

void write_to_file(char src_ip[], char dst_ip[], u_short src_port, u_short dst_port, char *packet, int payload_length, int protocol,
				   int ip_version, int payload_offset);

void init_file_sys();

void * file_sys(void * arg);