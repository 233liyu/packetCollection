//
// Created by lee yu on 2018/4/24.
//

#include <stdlib.h>
#include <pcap.h>
#include "ndpi_detection.h"
#include "ndpi_main.h"
#include "ndpi_api.h"
#include "ndpi_define.h"
#include "file_sys.h"

pthread_mutex_t packet_queue_mtx = PTHREAD_MUTEX_INITIALIZER;
// cond
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t con_mutex = PTHREAD_MUTEX_INITIALIZER;

struct packet_total * queue_header = NULL;

struct dpi_session{
	char * name_key;
	struct ndpi_flow_struct ndpi_sesion;
	uint64_t last_seen;

	uint32_t detected_protocol;
};

struct dpi_struct_t{
	struct ndpi_detection_module_struct * ndpi_struct;
};


/**
 * @brief malloc wrapper function
 */
static void *malloc_wrapper(size_t size) {
	return malloc(size);
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void free_wrapper(void *freeable) {
	free(freeable);
}

/* ***************************************************** */

/**
 * add a node into the queue for further usage
 * */
void add_node_to_queue(struct packet_total *node) {
	struct packet_total *ptr = NULL;

	struct ndpi_flow_struct pt;

	// lock the mutex to get access to the queue
	pthread_mutex_lock(&packet_queue_mtx);

	ptr = (struct packet_total *) queue_header;
	if (ptr != NULL) {
//		queue is not empty
		while (ptr->next_node != NULL) {
			ptr = ptr->next_node;
		}
		ptr->next_node = node;
//		unlock the mutex
		pthread_mutex_unlock(&packet_queue_mtx);
		pthread_cond_broadcast(&cond);
		return;
	} else {
//		queue is empty
		queue_header = node;
//		unlock the mutex
		pthread_mutex_unlock(&packet_queue_mtx);
		pthread_cond_broadcast(&cond);
		return;
	}

}

/**
 * return the first node in the queue, and return null if the queue is empty
 * */
struct packet_total *get_node_from_queue() {
	struct packet_total *ptr = NULL;

	pthread_mutex_lock(&packet_queue_mtx);
	ptr = (struct packet_total *) queue_header;
	if (ptr != NULL) {
//		queue is not empty
		queue_header = queue_header->next_node;
	} else {
//		queue is empty, return null
	}
	pthread_mutex_unlock(&packet_queue_mtx);
	return ptr;
}


/**
 * the main thread of the queue control
 * cope with getting packet from the queue
 * */
void *process_queue(void *arg) {
	struct packet_total *ptr = NULL;
	while (1) {

		ptr = get_node_from_queue();
		if (ptr != NULL) {


		} else {
//			the queue is empty
//			if wait for more than 1 second, thread will be waken
			struct timespec tim;
			tim.tv_sec = 1;
			tim.tv_nsec = 0;
			pthread_cond_timedwait(&cond, &con_mutex, &tim);
		}
	}
//		break
	return NULL;
}

/**
 * initializing the ndpi work flow
 * */

struct ndpi_workflow * ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs, pcap_t * pcap_handle) {
	int nDPI_LogLevel = 0;

	set_ndpi_malloc(malloc_wrapper);
	set_ndpi_free(free_wrapper);
	set_ndpi_flow_malloc(NULL);
	set_ndpi_flow_free(NULL);

	/* TODO: just needed here to init ndpi malloc wrapper */
	struct ndpi_detection_module_struct * module = ndpi_init_detection_module();

	struct ndpi_workflow * workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));

	workflow->pcap_handle = pcap_handle;
	workflow->ndpi_struct = module;

	if(workflow->ndpi_struct == NULL) {
		exit(-1);
	}

	module->ndpi_log_level = nDPI_LogLevel;


	workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

	return workflow;
}



struct dpi_session * get_ndpi_session(char * key){

}


/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
static struct ndpi_proto packet_processing(struct ndpi_workflow * workflow,
										   const u_int64_t time,
										   u_int16_t vlan_id,
										   const struct ndpi_iphdr *iph,
										   struct ndpi_ipv6hdr *iph6,
										   u_int16_t ip_offset,
										   u_int16_t ipsize, u_int16_t rawsize) {
	struct ndpi_id_struct *src, *dst;
	struct ndpi_flow_info *flow = NULL;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	u_int8_t proto;
	struct ndpi_tcphdr *tcph = NULL;
	struct ndpi_udphdr *udph = NULL;
	u_int16_t sport, dport, payload_len;
	u_int8_t *payload;
	u_int8_t src_to_dst_direction = 1;
	struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

	if(iph)
		flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id, iph, NULL,
								  ip_offset, ipsize,
								  ntohs(iph->tot_len) - (iph->ihl * 4),
								  &tcph, &udph, &sport, &dport,
								  &src, &dst, &proto,
								  &payload, &payload_len, &src_to_dst_direction);
	else
		flow = get_ndpi_flow_info6(workflow, vlan_id, iph6, ip_offset,
								   &tcph, &udph, &sport, &dport,
								   &src, &dst, &proto,
								   &payload, &payload_len, &src_to_dst_direction);

	if(flow != NULL) {
		workflow->stats.ip_packet_count++;
		workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
				workflow->stats.total_ip_bytes += rawsize;
		ndpi_flow = flow->ndpi_flow;

		if(src_to_dst_direction)
			flow->src2dst_packets++, flow->src2dst_bytes += rawsize;
		else
			flow->dst2src_packets++, flow->dst2src_bytes += rawsize;

		flow->last_seen = time;
	} else { // flow is NULL
		workflow->stats.total_discarded_bytes++;
		return(nproto);
	}

	/* Protocol already detected */
	if(flow->detection_completed) {
		if(flow->check_extra_packets && ndpi_flow != NULL && ndpi_flow->check_extra_packets) {
			if(ndpi_flow->num_extra_packets_checked == 0 && ndpi_flow->max_extra_packets_to_check == 0) {
				/* Protocols can set this, but we set it here in case they didn't */
				ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
			}
			if(ndpi_flow->num_extra_packets_checked < ndpi_flow->max_extra_packets_to_check) {
				ndpi_process_extra_packet(workflow->ndpi_struct, ndpi_flow,
										  iph ? (uint8_t *)iph : (uint8_t *)iph6,
										  ipsize, time, src, dst);
				if (ndpi_flow->check_extra_packets == 0) {
					flow->check_extra_packets = 0;
					process_ndpi_collected_info(workflow, flow);
				}
			}
		} else if (ndpi_flow != NULL) {
			/* If this wasn't NULL we should do the half free */
			/* TODO: When half_free is deprecated, get rid of this */
			ndpi_free_flow_info_half(flow);
		}

		return(flow->detected_protocol);
	}

	flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
															iph ? (uint8_t *)iph : (uint8_t *)iph6,
															ipsize, time, src, dst);

	if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
	   || ((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > 8))
	   || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > 10))) {
		/* New protocol detected or give up */
		flow->detection_completed = 1;
		/* Check if we should keep checking extra packets */
		if (ndpi_flow->check_extra_packets)
			flow->check_extra_packets = 1;

		if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
			flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct,
															flow->ndpi_flow);
		process_ndpi_collected_info(workflow, flow);
	}

	return(flow->detected_protocol);
}

