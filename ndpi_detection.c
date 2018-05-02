//
// Created by lee yu on 2018/4/24.
//

#include <stdlib.h>
#include "ndpi_detection.h"
#include "ndpi_main.h"
#include "ndpi_api.h"
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


/*
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

/*
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


/*
 * the main thread of the queue control
 * cope with getting packet from the queue
 * */
void *file_sys(void *arg) {
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




struct dpi_struct_t *init_dpi(dpi_server_config_t config, char *errbuf) {
	struct dpi_struct_t *dpi_struct = (struct dpi_struct_t *) malloc(sizeof(struct dpi_struct_t));
	if (dpi_struct == NULL) {
		snprintf(errbuf, BUFSIZ, "not enough memory");
		return NULL;
	}
	dpi_struct->ndpi_struct = ndpi_init_detection_module();
	if (dpi_struct->ndpi_struct == NULL) {
		snprintf(errbuf, BUFSIZ, "init ndpi error");
		dpi_free(dpi_struct);
		return NULL;
	}
	NDPI_PROTOCOL_BITMASK all;
	NDPI_BITMASK_SET_ALL(all);
	//去掉不需要的协议
	NDPI_BITMASK_DEL(all, NDPI_PROTOCOL_FTP_DATA);
	NDPI_BITMASK_DEL(all, NDPI_PROTOCOL_FTP_CONTROL);
	ndpi_set_protocol_detection_bitmask2(dpi_struct->ndpi_struct, &all);
	if (config.proto_file_path != NULL) {
		ndpi_load_protocols_file(dpi_struct->ndpi_struct, config.proto_file_path);
	}
	return dpi_struct;
}