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

#define NUM_ROOTS 500

pthread_mutex_t dpi_packet_queue_mtx = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond
pthread_cond_t pthread_cond_dpi = PTHREAD_COND_INITIALIZER;
pthread_mutex_t con_mutex_dpi = PTHREAD_MUTEX_INITIALIZER;

struct ndpi_packet *dpi_queue_header = NULL;
struct ndpi_system * work_system = NULL;

/**
 * struct to hold the session information
 * equal with the flow in ndpi
 * */
struct dpi_session {
	char *name_key;
	struct ndpi_flow_struct *ndpi_session;
	int ip_version;
	u_int hashval;
	uint64_t last_seen;
	ndpi_protocol detected_protocol;
	u_int8_t detection_completed, protocol, finished, check_extra_packets;
	u_int64_t packet_count;

	void *src_id, *dst_id;
};

/**
 * the main struct to keep the basic info of the dpi engine
 * contains with some basic settings
 * */
struct ndpi_system {
	struct ndpi_detection_module_struct *detection_module;
	void **session_root;
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
void dpi_add_node_to_queue(struct ndpi_packet *node) {
	struct ndpi_packet *ptr = NULL;

	struct ndpi_flow_struct pt;

	// lock the mutex to get access to the queue
	pthread_mutex_lock(&dpi_packet_queue_mtx);

	ptr = (struct ndpi_packet *) dpi_queue_header;
	if (ptr != NULL) {
//		queue is not empty
		while (ptr->next_node != NULL) {
			ptr = ptr->next_node;
		}
		ptr->next_node = node;
//		unlock the mutex
		pthread_mutex_unlock(&dpi_packet_queue_mtx);
		pthread_cond_broadcast(&pthread_cond_dpi);
		return;
	} else {
//		queue is empty
		dpi_queue_header = node;
//		unlock the mutex
		pthread_mutex_unlock(&dpi_packet_queue_mtx);
		pthread_cond_broadcast(&pthread_cond_dpi);
		return;
	}

}

/**
 * return the first node in the queue, and return null if the queue is empty
 * */
struct ndpi_packet *dpi_get_node_from_queue() {
	struct ndpi_packet *ptr = NULL;

	pthread_mutex_lock(&dpi_packet_queue_mtx);
	ptr = (struct ndpi_packet *) dpi_queue_header;
	if (ptr != NULL) {
//		queue is not empty
		dpi_queue_header = dpi_queue_header->next_node;
	} else {
//		queue is empty, return null
	}
	pthread_mutex_unlock(&dpi_packet_queue_mtx);
	return ptr;
}


static struct dpi_session * get_ndpi_session(struct ndpi_packet *packet, struct ndpi_system *work_sys,
											 struct ndpi_id_struct **src, struct ndpi_id_struct **dst) ;
static struct ndpi_proto packet_processing(struct ndpi_packet *packet, struct ndpi_system *work_sys) ;
/**
 * the main thread of the queue control
 * cope with getting packet from the queue
 * */
void * process_queue(void *arg) {
	struct ndpi_packet *ptr = NULL;
	while (1) {

		ptr = dpi_get_node_from_queue();
		if (ptr != NULL) {
#ifdef NDPI_DEBUG
			printf("\nqueue----------:\t%s",ptr->session_key);
#endif
			struct ndpi_proto proto = packet_processing(ptr, work_system);
		} else {
//			the queue is empty
//			if wait for more than 1 second, thread will be waken
			struct timespec tim;
			tim.tv_sec = 1;
			tim.tv_nsec = 0;
			pthread_cond_timedwait(&pthread_cond_dpi, &con_mutex_dpi, &tim);
		}
	}
	return NULL;
}

struct ndpi_packet *init_packet_node(char *ip_packet, int iphd_size, int tu_header_size,
									 int ip_version, int protocol, char *session_key, int payload_length, int total_length) {
	struct ndpi_packet *ptr = (struct ndpi_packet *) malloc(sizeof(struct ndpi_packet));
	ptr->packet = ip_packet;
	ptr->iphd_size = iphd_size;
	ptr->tu_header_size = tu_header_size;
	ptr->ip_version = ip_version;
	ptr->protocol = protocol;
	ptr->session_key = session_key;
	ptr->next_node = NULL;
	ptr->payload_length = payload_length;
	ptr->total_length = total_length;
	return ptr;
};


/**
 * exposed interface for main.c to give basic info of the packet
 * and send it to ndpi engine
 * */
void run_ndpi_detection(char *ip_packet, int iphd_size, int tu_header_size,
						int ip_version, int protocol, char *session_key, int payload_length, int total_length) {


	char *packet = (char *) malloc((size_t) total_length);

	for (int i = 0; i < total_length; ++i) {
		packet[i] = ip_packet[i];
	}

	struct ndpi_packet *pt = init_packet_node(packet, iphd_size, tu_header_size,
											  ip_version, protocol, session_key, payload_length,total_length);


	dpi_add_node_to_queue(pt);
}

//===============================queue management =========================================

/**
 * return a RShash value
 * */
unsigned int RSHash(char *str) {
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash = 0;
	while (*str) {
		hash = hash * a + (*str++);
		a *= b;
	}
	return (hash % NUM_ROOTS);
}

/**
 * initializing the ndpi work flow
 * */

void ndpi_workflow_init() {

	set_ndpi_malloc(malloc_wrapper);
	set_ndpi_free(free_wrapper);
	set_ndpi_flow_malloc(NULL);
	set_ndpi_flow_free(NULL);

	struct ndpi_detection_module_struct *module = ndpi_init_detection_module();

	struct ndpi_system *ndpi_sys = ndpi_calloc(1, sizeof(struct ndpi_system));

	ndpi_sys->detection_module = module;

	if (ndpi_sys->detection_module == NULL) {
		exit(-1);
	}

	ndpi_sys->session_root = ndpi_calloc(NUM_ROOTS, sizeof(void *));

	work_system = ndpi_sys;



}


/**
 * compare function for bi-tree search and build
 * use strcmp() to compare between name_keys
 * */
int ndpi_workflow_node_cmp(const void *a, const void *b) {
	struct dpi_session *fa = (struct dpi_session *) a;
	struct dpi_session *fb = (struct dpi_session *) b;

	int ret =  strcmp(fa->name_key, fb->name_key);
//	printf("\ncmp: %d: %s\t%s\n",ret, fa->name_key, fb->name_key);
	return ret;
}


static struct dpi_session * get_ndpi_session(struct ndpi_packet *packet, struct ndpi_system *work_sys,
											 struct ndpi_id_struct **src, struct ndpi_id_struct **dst) {
	u_int32_t idx, hashval;
	struct dpi_session flow;
	void *ret;


	flow.hashval = hashval = RSHash(packet->session_key);
	flow.name_key = packet->session_key;
	idx = hashval % NUM_ROOTS;

	ret = ndpi_tfind(&flow, &work_sys->session_root[idx], ndpi_workflow_node_cmp);


	if (ret == NULL) {

		struct dpi_session *newflow = (struct dpi_session *) malloc(sizeof(struct dpi_session));

		if (newflow == NULL) {
			NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
			return (NULL);
		}

		memset(newflow, 0, sizeof(struct dpi_session));
		newflow->hashval = hashval;
		newflow->protocol = (u_int8_t) packet->protocol;
		newflow->ip_version = packet->ip_version;
		newflow->packet_count = 0;
		newflow->finished = 0;
		newflow->name_key = packet->session_key;

		newflow->last_seen = (uint64_t) time;


		if ((newflow->ndpi_session = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
			NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
			free(newflow);
			return (NULL);
		} else
			memset(newflow->ndpi_session, 0, SIZEOF_FLOW_STRUCT);

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

		ndpi_tsearch(newflow, &work_sys->session_root[idx], ndpi_workflow_node_cmp); /* Add */

		*src = newflow->src_id, *dst = newflow->dst_id;

		return newflow;

	} else {
		// if session is not null
		struct dpi_session *n_flow = *(struct dpi_session**)ret;

		*src = n_flow->src_id, *dst = n_flow->dst_id;

		return n_flow;
	}
}

void process_ndpi_collected_info(struct ndpi_system * workflow, struct dpi_session *flow) {
	if(!flow->ndpi_session) return;

	ndpi_get_proto_by_id(workflow->detection_module, flow->detected_protocol.app_protocol);
	if(flow->detection_completed && !flow->check_extra_packets) {
		if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
			printf("\n=====give up!=========\n");
		} else {
			printf("\n=====flow detected! %s\t%s\n",ndpi_get_proto_by_id(workflow->detection_module, flow->detected_protocol.master_protocol), ndpi_get_proto_by_id(workflow->detection_module, flow->detected_protocol.app_protocol));
		}
		write_ndpi_protocol(flow->name_key,
							ndpi_get_proto_by_id(workflow->detection_module, flow->detected_protocol.master_protocol),
							ndpi_get_proto_by_id(workflow->detection_module, flow->detected_protocol.app_protocol));
		flow->finished = 1;
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
	int proto = packet->protocol;

	struct ndpi_proto nproto = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};
	struct dpi_session *flow = NULL;


	/*get flow from the ndpi session management*/
	flow = get_ndpi_session(packet, work_sys, &src, &dst);


	if (flow != NULL) {
		ndpi_flow = flow->ndpi_session;
		flow->packet_count++;
		flow->last_seen = (uint64_t) time;
	} else { // flow is NULL
		printf("ERROR! NO SESSION IS FOUND!!");
		return nproto;
	}

#ifdef NDPI_DEBUG
	printf("flow info:\n"
				   "\tkey: %s\n"
				   "\tcount: %llu\n"
				   "\tdetected:%d\n"
				   "\tdetected_ms_protocol: %d\n"
				   "\tdetected_app_protocol: %d\n"
				   "\tcheck_extra_packets: %d\n"
				   "\tndpi_check_packets:%d\n",
		   flow->name_key,flow->packet_count,flow->detection_completed,
		   flow->detected_protocol.master_protocol,flow->detected_protocol.app_protocol,
		   flow->check_extra_packets, flow->ndpi_session->check_extra_packets);
#endif
	/* Protocol already detected */
	if (flow->detection_completed) {
		if (flow->check_extra_packets && ndpi_flow != NULL && ndpi_flow->check_extra_packets) {
			if (ndpi_flow->num_extra_packets_checked == 0 && ndpi_flow->max_extra_packets_to_check == 0) {
				/* Protocols can set this, but we set it here in case they didn't */
				ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
			}
			if (ndpi_flow->num_extra_packets_checked < ndpi_flow->max_extra_packets_to_check) {
				ndpi_process_extra_packet(work_sys->detection_module, ndpi_flow,
										  (const unsigned char *) (packet->packet + SIZE_ETHERNET),
										  (const unsigned short) (packet->total_length - SIZE_ETHERNET),
										  (const u_int64_t) time, src, dst);
				if (ndpi_flow->check_extra_packets == 0) {
					flow->check_extra_packets = 0;
					if (!flow->finished){
						process_ndpi_collected_info(work_sys, flow);
					}
				}
			}
		} else if (ndpi_flow != NULL) {
			/* If this wasn't NULL we should do the half free */
			/* TODO: When half_free is deprecated, get rid of this */
//			ndpi_free_flow_info_half(flow);
		}
		if (!flow->finished){
			process_ndpi_collected_info(work_sys, flow);
		}
		return (flow->detected_protocol);
	}

#ifdef NDPI_DEBUG
	print_payload((const u_char *) (packet->packet + SIZE_ETHERNET +
			packet->iphd_size + packet->tu_header_size), packet->payload_length);
#endif
	flow->detected_protocol = ndpi_detection_process_packet(work_sys->detection_module, ndpi_flow,
															(const unsigned char *) (packet->packet + SIZE_ETHERNET),
															(const unsigned short) (packet->total_length - SIZE_ETHERNET),
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

		/**
		 * give up
		 * */
		if (!flow->finished){
			process_ndpi_collected_info(work_sys, flow);
		}
	}

	return (flow->detected_protocol);
}
