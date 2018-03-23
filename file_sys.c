//
// Created by lee yu on 2018/3/22.
//

#include <stdlib.h>
#include <pthread.h>
#include "file_sys.h"
#include "time.h"
#include "stdio.h"
#include "string.h"
#include "pcap_payload.h"

/*
 * the father dic of all packet
 * */
const char file_path[] = "";

const struct packet_total * queue_header = NULL;


/*
 * return current date in string format
 * yyyy-mm-dd
 * */
void get_date(char * str){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );

	/*
	 * potential risk of memory leak, by using sprintf
	 * the size off str must be longer than 10 chars
	 * */
	sprintf(str, "%04d-%02d-%02d",1900 + timeinfo->tm_year, timeinfo->tm_mon + 1, timeinfo->tm_mday);
}


//==================== queue management =======================

struct packet_total * init_node(char * src, char * dst, char * payload, int length, int protocol){
	struct packet_total * ptr = NULL;
	ptr = (struct packet_total *) malloc (sizeof(struct packet_total));
	ptr->next_node = NULL;

	ptr->dst_add = dst;
	ptr->src_add = src;
	ptr->payload = payload;
	ptr->length = length;
	ptr->protocol = protocol;

	printf("debug: \n"
				   "create node : \n"
				   "src: %s\t dst: %s\n"
				   "payload size: %d",
	ptr->src_add,ptr->dst_add,ptr->length);
	return ptr;
}

void delete_node(struct packet_total * ptr){
	free(ptr->src_add);
	free(ptr->dst_add);
	free(ptr->payload);
	free(ptr);
}

/*
 * add a node into the queue for further usage
 * */
void add_node_to_queue(struct packet_total * node){
	struct packet_total * ptr = NULL;

	ptr = (struct packet_total*) queue_header;
	if (ptr != NULL){
//		queue is not empty
		while (ptr->next_node != NULL){
			ptr = ptr->next_node;
		}
		ptr->next_node = node;
		return;
	} else {
//		queue is empty
		queue_header = node;
		return;
	}

}

/*
 * return the first node in the queue, and return null if the queue is empty
 * */
struct packet_total * get_node_from_queue(){
	struct packet_total * ptr = NULL;

	ptr = (struct packet_total*) queue_header;
	if (ptr != NULL){
//		queue is not empty
		queue_header = queue_header->next_node;
		return ptr;
	} else {
//		queue is empty return null
		return ptr;
	}
}




/*
 * exposed interface to main.c to provide basic info of the packet
 * after adding the node to the queue, file writing will be handled by the file sys
 * */
void write_to_file(char src_ip[], char dst_ip[], u_short src_port, u_short dst_port, char * payload, int length, int protocol){
	char  * src, * dst = NULL;
	src = (char *)malloc(sizeof(char) * (strlen(src_ip) + 20));
	dst = (char *)malloc(sizeof(char) * (strlen(dst_ip) + 20));

	sprintf(src, "%s-%d",src_ip,ntohs(src_port));
	sprintf(dst, "%s-%d",dst_ip,ntohs(dst_port));

	char * pl = (char *)malloc(sizeof(char) * length);
	printf("length: %d\t, pl_length:%d\n",length, (int)sizeof(char) * length);
	strncpy(pl,payload,length);

	struct packet_total * ptr = init_node(src,dst,pl,length,protocol);

	//add to queue;

	delete_node(ptr);
}


/*
 * initial the file system, basic set up for the thread control;
 * */
void init_file_sys(){
	return;
}