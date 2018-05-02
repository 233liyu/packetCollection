//
// Created by lee yu on 2018/3/22.
//

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include "file_sys.h"
#include "stdio.h"
#include "string.h"
#include "pcap_payload.h"
#include "proc.h"
#include "ndpi_api.h"

#define LY_SRC = 0;
#define LY_DST = 1;
#define LY_BDC = 2;


/*
 * the father dic of all packet
 * */
#if defined(__APPLE__)
const char file_path[] = "/Users/lee/Desktop/大四/毕业设计/GP_data";
#elif defined(linux)
const char file_path[] = "/home/lee/Desktop/GP";
#endif

const struct packet_total *queue_header = NULL;
// queue mutex control the access of the queue
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
// cond
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t con_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * return current date in string format
 * yyyy-mm-dd
 * */
void get_date(char *str) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    /*
     * potential risk of memory leak, by using sprintf
     * the size off str must be longer than 10 chars
     * */
    sprintf(str, "%04d-%02d-%02d", 1900 + timeinfo->tm_year, timeinfo->tm_mon + 1, timeinfo->tm_mday);
}


//==================== queue management =======================

struct packet_total *init_node(char *src, char *dst, char *payload, int length, int protocol, int version) {
    struct packet_total *ptr = NULL;
    ptr = (struct packet_total *) malloc(sizeof(struct packet_total));
    ptr->next_node = NULL;

    ptr->dst_add = dst;
    ptr->src_add = src;
    ptr->payload = payload;
    ptr->length = length;
    ptr->protocol = protocol;
    ptr->ip_version = version;

    printf("debug: \n"
                   "create node : \n"
                   "src: %s\t dst: %s\n"
                   "payload size: %d",
           ptr->src_add, ptr->dst_add, ptr->length);
    return ptr;
}

void delete_node(struct packet_total *ptr) {
    free(ptr->src_add);
    free(ptr->dst_add);
    free(ptr->payload);
    free(ptr);
}

/*
 * add a node into the queue for further usage
 * */
void add_node_to_queue(struct packet_total *node) {
    struct packet_total *ptr = NULL;

    // lock the mutex to get access to the queue
    pthread_mutex_lock(&queue_mutex);

    ptr = (struct packet_total *) queue_header;
    if (ptr != NULL) {
//		queue is not empty
        while (ptr->next_node != NULL) {
            ptr = ptr->next_node;
        }
        ptr->next_node = node;
//		unlock the mutex
        pthread_mutex_unlock(&queue_mutex);
        pthread_cond_broadcast(&cond);
        return;
    } else {
//		queue is empty
        queue_header = node;
//		unlock the mutex
        pthread_mutex_unlock(&queue_mutex);
        pthread_cond_broadcast(&cond);
        return;
    }

}

/*
 * return the first node in the queue, and return null if the queue is empty
 * */
struct packet_total *get_node_from_queue() {
    struct packet_total *ptr = NULL;

    pthread_mutex_lock(&queue_mutex);
    ptr = (struct packet_total *) queue_header;
    if (ptr != NULL) {
//		queue is not empty
        queue_header = queue_header->next_node;
    } else {
//		queue is empty, return null
    }
    pthread_mutex_unlock(&queue_mutex);
    return ptr;
}


/*
 * exposed interface to main.c to provide basic info of the packet
 * after adding the node to the queue, file writing will be handled by the file sys
 * */
void
write_to_file(char src_ip[], char dst_ip[], u_short src_port, u_short dst_port, char *packet, int payload_length, int protocol,
              int ip_version, int payload_offset) {
    char *src, *dst = NULL;
    src = (char *) malloc(sizeof(char) * (strlen(src_ip) + 20));
    dst = (char *) malloc(sizeof(char) * (strlen(dst_ip) + 20));

    sprintf(src, "%s-%d", src_ip, ntohs(src_port));
    sprintf(dst, "%s-%d", dst_ip, ntohs(dst_port));

    char *pl = (char *) malloc(sizeof(char) * payload_length);

//	copy the payload to pl, in order to create the node
    for (int i = 0; i < payload_length; ++i) {
        char vc = packet[i + payload_offset];
        pl[i] = vc;
    }

    struct packet_total *ptr = init_node(src, dst, pl, payload_length, protocol, ip_version);\

    //add to queue;
    add_node_to_queue(ptr);


}


// ============================= file writing  ======================================

/*
 * initial the file system, basic set up for the thread control;
 * */
void init_file_sys() {


    return;
}


/*
 * get the name of the file
 * create a unique file name for the grand use
 * */
void create_file_name(struct packet_total *ptr, char *bufffer) {
//	"src-port*dst-port*TCP"
//   start with local address
    if (is_local_ip(ptr->src_add)){
//        if the local address is the source address
        if (ptr->protocol == LY_TCP){
            sprintf(bufffer,"%s*%s*TCP",ptr->src_add,ptr->dst_add);
        } else {
            sprintf(bufffer,"%s*%s*UDP",ptr->src_add,ptr->dst_add);
        }

    } else if (is_local_ip(ptr->dst_add)){
//        if the local address is the destination address
        if (ptr->protocol == LY_TCP){
            sprintf(bufffer,"%s*%s*TCP",ptr->dst_add,ptr->src_add);
        } else {
            sprintf(bufffer,"%s*%s*UDP",ptr->dst_add,ptr->src_add);
        }
    } else {
//        the packet is a broadcast message
        if (ptr->protocol == LY_TCP){
            sprintf(bufffer,"%s*%s*TCP",ptr->src_add,ptr->dst_add);
        } else {
            sprintf(bufffer,"%s*%s*UDP",ptr->src_add,ptr->dst_add);
        }
    }
}

void write_processInfo(char * file_name, char * ip_info, int ip_version){
    char result [10240] = "";
    char ip_port [1024] = "";
    strcpy(ip_port, ip_info);
    char * cc = strstr(ip_port,"*");
    *cc = '\0';
    get_proc_info(ip_port,ip_version,result);

    FILE * fp = NULL;
    fp = fopen(file_name,"w+");
    if (fp == NULL){
        printf("error create file %s\n", file_name);
    } else {
        fprintf(fp,"%s\n", result);
        fclose(fp);
    }
}


/*
 * create file dic if needed
 * create file if not exist
 * */
void init_file(struct packet_total *ptr, char * file_name) {

    char name_buffer[1024] = "";
    char total_buffer[2048] = "";
    char date_buffer[50] = "";

    create_file_name(ptr,name_buffer);
    get_date(date_buffer);

    sprintf(total_buffer,"%s/%s",file_path,date_buffer);
    if (access(total_buffer,F_OK)){
//        dic not exist!
        if (mkdir(total_buffer,0777) == 0){
            printf("dic %s created!\n", total_buffer);
        } else {
            printf("error creating file dic %s\n", total_buffer);
        }
    }

    strcat(total_buffer,"/");
    strcat(total_buffer,name_buffer);
    strcpy(file_name,total_buffer);

    if (access(total_buffer,F_OK)){
//        file not exist!
//        create file and write the process info
        write_processInfo(total_buffer,name_buffer,ptr->ip_version);
    }

}

void write_file(struct packet_total *ptr) {

    char file_name[2048] = "";

    init_file(ptr,file_name);

    FILE * fp = NULL;
    fp = fopen(file_name,"a+");
    if (fp == NULL){
        printf("error opening file %s\n", file_name);
    } else {
        fprintf(fp, "\nsrc: %s\tdst: %s\tpayload length:%d\n",ptr->src_add,ptr->dst_add,ptr->length);
        u_char * ch = (u_char *)ptr->payload;
        for (int j = 0; j < ptr->length; ++j) {
            fprintf(fp, "%02x", *ch);
            ch ++;
        }
        fclose(fp);
    }
}


/*
 * the main thread of the file system
 * cope with getting packet from the queue
 * */
void *file_sys(void *arg) {
    struct packet_total *ptr = NULL;
    while (1) {

        ptr = get_node_from_queue();
        if (ptr != NULL) {

            write_file(ptr);

            delete_node(ptr);
            printf("node deleted===============\n");
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


