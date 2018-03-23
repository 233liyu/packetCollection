//
// Created by lee on 18-3-11.
//

#include <ctype.h>
#include <arpa/inet.h>
#include "pcap_payload.h"
#include "stdio.h"

/*\
 * print data in rows of 16 bytes: offset   \   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;            /* number of bytes per line */
	int line_len;
	int offset = 0;                    /* zero-based offset counter */\
	u_char *ch = (u_char *)payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
 * judge the version of the ip packets
 * return 0 for ipv4 and 1 for ipv6
 * */
int ip_version(u_char * packet){
	u_char version;
	version = *packet;
	version = version & (u_char)0xf0;
	if (version == 0x40){
		return LY_ipv4;
	} else if (version == 0x60){
		return LY_ipv6;
	} else {
		printf("version error\n");
	}
	return -1;
}

/*
 * return the size of the ip headers, in order to count the offset of ip payload
 * return 0 for error, ipv6 header length is fixed
 * ignore the tunnelling \
 * */
int ip_header_size(u_char * packet){
	int ip_ver = 0;
	int size_t = 0;

	ip_ver = ip_version(packet);
	struct ipv4_header * ip = (struct ipv4_header *) (packet);

	switch (ip_ver) {
		case LY_ipv4:
			//ipv4
			size_t = (ip->ip_vhl & 0x0f) * 4;
			if (size_t < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_t);
				size_t = 0;
			}
			break;
		case LY_ipv6:
			// ipv6 header length is fixed 320 bits -> 40 bytes

			size_t = 40;
			break;
		default:break;
	}

	return size_t;
}

/*
 * try to return the protocol of the ip packet,
 * in this case, the function will only compare TCP/UDP, other protocol will be ignored
 *
 * return value :
 * 	-1 for other protocol;
 * 	0  for TCP
 * 	1  for UDP
 * */
int bytes2protocol(u_char * protocol_bytes){

	int protocol = -1;
	/* determine protocol */
	switch (*protocol_bytes) {
		case IPPROTO_TCP:
			protocol = LY_TCP;
			break;
		case IPPROTO_UDP:
			protocol = LY_UDP;
			break;
		default:
			printf("   Protocol: other 0x%02x\n", *protocol_bytes);
			break;
	}
	return protocol;
}

/*
 * exported API for protocol check
 * return LY_TCP for TCP protocol
 * return -1 for error
 * */
int ip_protocol(u_char * ip_packet){
	struct ipv4_header * ipv4 = NULL;
	struct ipv6_header * ipv6 = NULL;
	switch (ip_version(ip_packet)){
		case LY_ipv4:
			ipv4 = (struct ipv4_header *)ip_packet;
			return bytes2protocol(&ipv4->ip_p);
		case LY_ipv6:
			ipv6 = (struct ipv6_header *)ip_packet;
			return bytes2protocol(&ipv6->ip_nextHeader);
		default:
			return -1;
	}
}

void print_ip_add(u_char * ip_packet, char * src_ip, char * dst_ip){
	struct ipv4_header * ipv4 = NULL;
	struct ipv6_header * ipv6 = NULL;
	char str[255] = "";
	switch (ip_version(ip_packet)){
		case LY_ipv4:
			ipv4 = (struct ipv4_header *)ip_packet;
			/* print source and destination IP addresses */
			if(inet_ntop(AF_INET, &ipv4->ip_src, str, sizeof (str))){
				printf("       From: %s\n", str);
				sprintf(src_ip,"%s",str);
			}
			if(inet_ntop(AF_INET, &ipv4->ip_dst, str, sizeof (str))){
				printf("         To: %s\n", str);
				sprintf(dst_ip,"%s",str);
			}
			break;
		case LY_ipv6:
			ipv6 = (struct ipv6_header *)ip_packet;
			if(inet_ntop(AF_INET6, &ipv6->ip_src, str, sizeof (str))){
				printf("       From: %s\n", str);
				sprintf(src_ip,"%s",str);
			}
			if(inet_ntop(AF_INET6, &ipv6->ip_dst, str, sizeof (str))){
				printf("         To: %s\n", str);
				sprintf(dst_ip,"%s",str);
			}
			break;
		default:
			break;
	}
}

void print_ports(u_char * tu_header){
	struct bw_port b_port;
	get_port(tu_header, &b_port);
	printf("source port     : %d \n", ntohs(b_port.src_port));
	printf("destination port: %d \n", ntohs(b_port.des_port));
}

/*
 * help to translate the port,
 * works with both TCP and UDP
 * */
void get_port(u_char * header, struct bw_port * ports){
	struct bw_port * ptr = (struct bw_port *) header;
	ports->src_port = ptr->src_port;
	ports->des_port = ptr->des_port;
}

/*
 * compute the size of the TCP header, UDP header size is fixed 8 bytes
 * */
int TCP_header_size(u_char * header){
	int size = 0;
	struct TCP_header * h1 = (struct TCP_header *)header;
	size = TH_OFF(h1) * 4;
	return  size;
}

/*
 * compute the size of the TCP payload size
 * */
int TCP_payload_size(u_char * ip){
	int ip_hsize = ip_header_size(ip);
	int version = ip_version(ip);

	if(version == LY_ipv4){
		struct ipv4_header * ih4 = (struct ipv4_header *)ip;

		int ip_tsize = ntohs(ih4->ip_len);
		int tcp_hsize = TCP_header_size(ip + ip_hsize);
		if (tcp_hsize == 0){
			// tcp header error
			return 0;
		}
		// ip packet total size - ip header size - tcp header size
		return ip_tsize - (ip_hsize + tcp_hsize);

	} else if (version == LY_ipv6){
		struct ipv6_header * ih6 = (struct ipv6_header *)ip;
		int ip_plsize = ntohs(ih6->ip_pllength);
		int tcp_hsize = TCP_header_size(ip + ip_hsize);
		if (tcp_hsize == 0){
			// tcp header error
			return 0;
		}
		// ip payload size - tcp header size
		return ip_plsize - tcp_hsize;
	}
	return 0;
}

/*
 * the size of UDP payload
 * */
int UDP_payload_size(u_char * ip){
	int ip_hsize = ip_header_size(ip);

	struct UDP_header * udp = (struct UDP_header *) (ip + ip_hsize);
	int ret = ntohs(udp->total_length);
	return ret - 8;
}