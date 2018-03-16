//
// Created by lee on 18-3-11.
//

#ifndef LIBPCAP_PCAP_PAYLOAD_H
#define LIBPCAP_PCAP_PAYLOAD_H


#endif //LIBPCAP_PCAP_PAYLOAD_H

#include <sys/param.h>
#include <netinet/in.h>



#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IPv4 header */
struct ipv4_header {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};


/* IPv6 header*/
struct ipv6_header{
    u_char ip_vtcu;                 /* version << 4 | traffic class up >> 2 */
    u_char ip_tcdfl;                /* traffic class 4 bits + flow label*/
    u_short ip_flowlable;           /* flow label*/
    u_short ip_pllength;            /* payload length*/
    u_char ip_nextHeader;			/* next header 8 bits, tells the protocols or extension headers*/
    u_char ip_hplimit;
    struct in6_addr ip_src,ip_dst;
};


#define LY_TCP 0
#define LY_UDP 1

#define LY_ipv4 0
#define LY_ipv6 1


/* TCP header */
typedef u_int tcp_seq;

struct TCP_header {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char th_offx2;               /* data offset, rsvd */
    u_char th_flags;
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

/*
 * UDP headers
 * */
struct UDP_header{
	u_short src_port;				/* source port */
	u_short dst_port;				/* destination port*/
	u_short total_length;			/* total length of the UDP, >= 8bytes*/
	u_short sum;					/* check sum*/
};

/*
 * a struct combined with source port and destination port
 * */
struct bw_port{
	u_short src_port;
	u_short des_port;
};
/*
 * functions :
 * */


void print_payload(const u_char * payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

int ip_version(u_char * packet);

int ip_header_size(u_char * packet);

int ip_protocol(u_char * ip_packet);

void print_ip_add(u_char * ip_packet);

void print_ports(u_char * tu_header);

void get_port(u_char * header, struct bw_port * ports);

int TCP_header_size(struct TCP_header * header);

int TCP_payload_size(u_char * ip);

int UDP_payload_size(u_char * ip);