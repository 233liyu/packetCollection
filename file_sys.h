//
// Created by lee yu on 2018/3/22.
//

//

#ifndef LIBPCAP_FILE_SYS_H
#define LIBPCAP_FILE_SYS_H

#endif //LIBPCAP_FILE_SYS_H

struct packet_total{
	// "ip.ip.ip.ip:port"
	char * src_add;
	char * dst_add;

	char * payload;
	int length;
	int protocol;

	struct packet_total * next_node;
};

void write_to_file(char src_ip[], char dst_ip[], u_short src_port, u_short dst_port, char * payload, int length, int protocol);

void init_file_sys();

void * file_sys(void * arg);