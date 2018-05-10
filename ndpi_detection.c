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
#include "pcap_payload.h"

pthread_mutex_t packet_queue_mtx = PTHREAD_MUTEX_INITIALIZER;
// cond
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t con_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ndpi_packet *queue_header = NULL;

/**
 * struct to hold the session information
 * equal with the flow in ndpi
 * */
struct dpi_session {
	char *name_key;
	struct ndpi_flow_struct *ndpi_session;
	int ip_version;
	uint64_t last_seen;
	ndpi_protocol detected_protocol;
	u_int8_t detection_completed, protocol, bidirectional, check_extra_packets;
	u_int64_t packet_count;
};

/**
 * the main struct to keep the basic info of the dpi engine
 * contains with some basic settings
 * */
struct ndpi_system {
	struct ndpi_detection_module_struct *detection_module;
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
void add_node_to_queue(struct ndpi_packet *node) {
	struct ndpi_packet *ptr = NULL;

	struct ndpi_flow_struct pt;

	// lock the mutex to get access to the queue
	pthread_mutex_lock(&packet_queue_mtx);

	ptr = (struct ndpi_packet *) queue_header;
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
	struct ndpi_packet *ptr = NULL;

	pthread_mutex_lock(&packet_queue_mtx);
	ptr = (struct ndpi_packet *) queue_header;
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
	struct ndpi_packet *ptr = NULL;
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
	return NULL;
}

struct ndpi_packet *init_packet_node(char *ip_packet, int iphd_offset, int payload_offset,
									 int ip_version, int protocol, char *session_key, int payload_length) {
	struct ndpi_packet *ptr = (struct ndpi_packet *) malloc(sizeof(struct ndpi_packet));
	ptr->ip_packet = ip_packet;
	ptr->iphd_offset = iphd_offset;
	ptr->payload_offset = payload_offset;
	ptr->ip_version = ip_version;
	ptr->protocol = protocol;
	ptr->session_key = session_key;
	ptr->next_node = NULL;
	ptr->payload_length = payload_length;
	return ptr;
};


/**
 * exposed interface for main.c to give basic info of the packet
 * and send it to ndpi engine
 * */
void run_ndpi_detection(char *ip_packet, int iphd_offset, int payload_offset,
						int ip_version, int protocol, char *session_key, int payload_length) {
	int total_length = payload_offset + payload_length;

	char *packet = (char *) malloc((size_t) total_length);

	for (int i = 0; i < total_length; ++i) {
		packet[i] = ip_packet[i];
	}

	struct ndpi_packet *pt = init_packet_node(packet, iphd_offset, payload_offset,
											  ip_version, protocol, session_key, payload_length);

	add_node_to_queue(pt);
}

//===============================queue management =========================================

/**
 * initializing the ndpi work flow
 * */

struct ndpi_system *ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs, pcap_t *pcap_handle) {
	int nDPI_LogLevel = 0;

	set_ndpi_malloc(malloc_wrapper);
	set_ndpi_free(free_wrapper);
	set_ndpi_flow_malloc(NULL);
	set_ndpi_flow_free(NULL);

	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();

	struct ndpi_system *ndpi_sys = ndpi_calloc(1, sizeof(struct ndpi_sys));

	ndpi_sys->detection_module = module;

	if (ndpi_sys->detection_module == NULL) {
		exit(-1);
	}

//	ndpi_sys->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

	return ndpi_sys;
}


/**
 * compare function for bi-tree search and build
 * use strcmp() to compare between name_keys
 * */
int ndpi_workflow_node_cmp(const void *a, const void *b) {
	struct dpi_session *fa = (struct dpi_session *) a;
	struct dpi_session *fb = (struct dpi_session *) b;

	return strcmp(fa->name_key, fb->name_key);
}


static struct dpi_session *get_ndpi_session(struct ndpi_packet *packet, struct ndpi_system * work_sys) {
	u_int32_t idx, l4_offset, hashval;
	struct dpi_session flow;
	void *ret;
	u_int8_t *l3, *l4;



	flow.protocol = (u_int8_t) packet->protocol;
	flow.hashval = hashval = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port;
	idx = hashval % workflow->prefs.num_roots;
	ret = ndpi_tfind(&flow, &->ndpi_flows_root[idx], ndpi_workflow_node_cmp);


	/* to avoid two nodes in one binary tree for a flow */
	int is_changed = 0;
	if (ret == NULL) {
		u_int32_t orig_src_ip = flow.src_ip;
		u_int16_t orig_src_port = flow.src_port;
		u_int32_t orig_dst_ip = flow.dst_ip;
		u_int16_t orig_dst_port = flow.dst_port;

		flow.src_ip = orig_dst_ip;
		flow.src_port = orig_dst_port;
		flow.dst_ip = orig_src_ip;
		flow.dst_port = orig_src_port;

		is_changed = 1;

		ret = ndpi_tfind(&flow, &work_sys->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
	}

	if (ret == NULL) {
		if (workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
			NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR,
					 "maximum flow count (%u) has been exceeded\n",
					 workflow->prefs.max_ndpi_flows);
			exit(-1);
		} else {
			struct ndpi_flow_info *newflow = (struct ndpi_flow_info *) malloc(sizeof(struct ndpi_flow_info));

			if (newflow == NULL) {
				NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
				return (NULL);
			} else
				workflow->num_allocated_flows++;

			memset(newflow, 0, sizeof(struct ndpi_flow_info));
			newflow->hashval = hashval;
			newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
			newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
			newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
			newflow->ip_version = version;

			if (version == IPVERSION) {
				inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
				inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
			} else {
				inet_ntop(AF_INET6, &iph6->ip6_src, newflow->src_name, sizeof(newflow->src_name));
				inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->dst_name, sizeof(newflow->dst_name));
				/* For consistency across platforms replace :0: with :: */
				patchIPv6Address(newflow->src_name), patchIPv6Address(newflow->dst_name);
			}

			if ((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
				NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
				free(newflow);
				return (NULL);
			} else
				memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

			if ((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
				NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
				free(newflow);
				return (NULL);
			} else
				memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

			if ((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
				NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
				free(newflow);
				return (NULL);
			} else
				memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

			ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp); /* Add */
			workflow->stats.ndpi_flow_count++;

			*src = newflow->src_id, *dst = newflow->dst_id;

			return newflow;
		}
	} else {
		struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) ret;

		if (is_changed) {
			if (flow->src_ip == iph->saddr
				&& flow->dst_ip == iph->daddr
				&& flow->src_port == htons(*sport)
				&& flow->dst_port == htons(*dport)
					)
				*src = flow->dst_id, *dst = flow->src_id, *src_to_dst_direction = 0, flow->bidirectional = 1;
			else
				*src = flow->src_id, *dst = flow->dst_id, *src_to_dst_direction = 1;
		} else {
			if (flow->src_ip == iph->saddr
				&& flow->dst_ip == iph->daddr
				&& flow->src_port == htons(*sport)
				&& flow->dst_port == htons(*dport)
					)
				*src = flow->src_id, *dst = flow->dst_id, *src_to_dst_direction = 1;
			else
				*src = flow->dst_id, *dst = flow->src_id, *src_to_dst_direction = 0, flow->bidirectional = 1;
		}
		return flow;
	}
}


/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: ndpi_proto from ndpi_detection_process_packet() or {0,0}
*/
static struct ndpi_proto packet_processing(struct ndpi_packet *packet, struct ndpi_system *work_sys) {
	/* set src and dst to default according to the ndpi demo*/
	struct ndpi_id_struct *src, *dst;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	u_int8_t proto = (u_int8_t) packet->protocol;

	struct ndpi_proto nproto = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};
	struct dpi_session *flow = NULL;

	/*get flow from the ndpi session management*/
	flow = get_ndpi_session(packet);

	if (flow != NULL) {
		ndpi_flow = flow->ndpi_session;
		flow->packet_count ++;
		flow->last_seen = (uint64_t) time;
	} else { // flow is NULL
		printf("ERROR! NO SESSION IS FOUND!!");
		return nproto;
	}

	/* Protocol already detected */
	if (flow->detection_completed) {
		if (flow->check_extra_packets && ndpi_flow != NULL && ndpi_flow->check_extra_packets) {
			if (ndpi_flow->num_extra_packets_checked == 0 && ndpi_flow->max_extra_packets_to_check == 0) {
				/* Protocols can set this, but we set it here in case they didn't */
				ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
			}
			if (ndpi_flow->num_extra_packets_checked < ndpi_flow->max_extra_packets_to_check) {
				ndpi_process_extra_packet(work_sys->detection_module, ndpi_flow,
										  (const unsigned char *) (packet->ip_packet + packet->iphd_offset),
										  (const unsigned short) (packet->payload_offset - packet->iphd_offset),
										  (const u_int64_t) time, src, dst);
				if (ndpi_flow->check_extra_packets == 0) {
					flow->check_extra_packets = 0;
				}
			}
		} else if (ndpi_flow != NULL) {
			/* If this wasn't NULL we should do the half free */
			/* TODO: When half_free is deprecated, get rid of this */
//			ndpi_free_flow_info_half(flow);
		}

		return (flow->detected_protocol);
	}

	flow->detected_protocol = ndpi_detection_process_packet(work_sys->detection_module, ndpi_flow,
															(const unsigned char *) (packet->ip_packet +
																					 packet->iphd_offset),
															(const unsigned short) (packet->payload_offset -
																					packet->iphd_offset),
															(const u_int64_t) time, src, dst);

	if ((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
		|| ((proto == LY_UDP) && ((flow->packet_count) > 8))
		|| ((proto == LY_TCP) && ((flow->packet_count) > 10))) {
		/* New protocol detected or give up */
		flow->detection_completed = 1;
		/* Check if we should keep checking extra packets */
		if (ndpi_flow->check_extra_packets)
			flow->check_extra_packets = 1;

		if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
			flow->detected_protocol = ndpi_detection_giveup(work_sys->detection_module,
															flow->ndpi_session);
	}

	return (flow->detected_protocol);
}

