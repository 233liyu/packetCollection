#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "pcap_payload.h"
#include "file_sys.h"
#include "ndpi_detection.h"


void call_back(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * dissect/print packet
 */
void call_back(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct ipv4_header *ip;              /* The IP header */
    const struct TCP_header *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    char src_ip[255] = "";
    char dst_ip[255] = "";
    const struct bw_port ports;

    int protocol = 0;


//    printf("\n\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet *) (packet);

    /* define/compute ip header offset */
    ip = (struct ipv4_header *) (packet + SIZE_ETHERNET);

    /* define the version of the ip */
    int IP_version = ip_version((u_char *) ip);

    memset(src_ip, '\0', sizeof(src_ip));
    memset(dst_ip, '\0', sizeof(dst_ip));

    switch (IP_version) {
        case LY_ipv4:
        case LY_ipv6:
            print_ip_add((u_char *) ip, src_ip, dst_ip);
            break;
        default:
            printf("error: cannot read the version of the packet!");
            return;
    }

    int ip_hsize = ip_header_size((u_char *) (ip));

    if (ip_hsize == 0) {
        // if the ip header length is not valid
        printf("error: ip header error! ");
        return;
    }


    int payload_size = 0;
    int tu_header_size = 0;

    switch (ip_protocol((u_char *) ip)) {
        case LY_TCP:
            protocol = LY_TCP;
            payload_size = TCP_payload_size((u_char *) ip);
            tu_header_size = TCP_header_size((u_char *) (packet + SIZE_ETHERNET + ip_hsize));
#ifdef PACKET_DEBUG
			printf("TCP payload size : %d\n", payload_size);
			printf("TCP header length :  %d\n", tu_header_size);
			print_ports((u_char *) (packet + SIZE_ETHERNET + ip_hsize));
#endif
			tcp = (struct TCP_header *) (packet + SIZE_ETHERNET + ip_hsize);

            if (tu_header_size < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", tu_header_size);
                return;
            }
            get_port((u_char *) tcp, (struct bw_port *) &ports);
            break;
        case LY_UDP:
            protocol = LY_UDP;
            payload_size = UDP_payload_size((u_char *) ip);
            tu_header_size = 8;
			get_port((u_char *) (packet + SIZE_ETHERNET + ip_hsize), (struct bw_port *) &ports);

#ifdef PACKET_DEBUG
			printf("UDP payload size : %d\n", payload_size);
			print_ports((u_char *) (packet + SIZE_ETHERNET + ip_hsize));
#endif
            break;
        default:
            // do not handle other protocol and forget about the tunnelling or ip in ip encapsulation
            printf(" unknown protocol");
            return;
    }


    /* define/compute tcp payload (segment) offset */
    payload = (char *) (packet + SIZE_ETHERNET + ip_hsize + tu_header_size);


    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */


	char * index = create_grand_index(src_ip, dst_ip, ports.src_port, ports.des_port, protocol,IP_version);

	run_ndpi_detection((char *)packet, ip_hsize, tu_header_size, IP_version,
					   protocol, index, payload_size, header->caplen);


    if (payload_size > 0) {

#ifdef PACKET_DEBUG
		printf("   Payload (%d bytes):\n", payload_size);
		print_payload((u_char *)payload, payload_size);
#endif

        write_to_file(src_ip, dst_ip, ports.src_port, ports.des_port, (char *) packet, payload_size, protocol,
                      IP_version, SIZE_ETHERNET + ip_hsize + tu_header_size);
    }


    return;
}

int main(int argc, char **argv) {

    char *dev = NULL;            /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */

    char filter_exp[] = "ip or ip6";        /* filter expression [3] */

    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */


    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        exit(EXIT_FAILURE);
    } else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /**
     * set up the file writing thread
     * start 1 threads by default
     *
     * !!! DO NOT SUPPORT MORE THREAD IN CURRENT VERSION
     *
     * */
    pthread_t *file_thread_pool = NULL;
    int thread_num = 1;
    file_thread_pool = (pthread_t *) malloc(sizeof(pthread_t) * thread_num);

    for (int i = 0; i < thread_num; ++i) {
        pthread_create(&file_thread_pool[i], NULL, file_sys, NULL);
    }


	ndpi_workflow_init();

	pthread_t *ndpi_thread = NULL;
	ndpi_thread = (pthread_t *) malloc(sizeof(pthread_t) );
	pthread_create(ndpi_thread, NULL, process_queue, NULL);



	/* now we can set our callback function */
    pcap_loop(handle, -1, call_back, NULL);


    for (int j = 0; j < thread_num; ++j) {
        pthread_join(file_thread_pool[j], NULL);
    }


    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}
