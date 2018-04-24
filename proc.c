//
// Created by lee yu on 2018/4/2.
//


/*
 * created in order to call lsof to get the process details at the moment of the file is being created
 * */

#include "proc.h"
#include "pcap_payload.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "khash.h"
//#include "pthread.h"

static char * local_ip = NULL;



/*
 * start a pip to lsof command to get the process info of the connect
 * and return the result to the * result
 * "lsof -i @ipv4.ipv4.ipv4.ipv4:port"
 * "lsof -i @[ipv6:ipv6::]:port"
 * */

int get_proc_info(char *ip_port_t, int ip_version, char *result) {
    char buffer[10240];

    char cmd_buffer[1024] = "";
    char ip_port [1024] = "";
    char *cc = "-";

    strcpy(ip_port, ip_port_t);
    if (ip_version == LY_ipv4) {
        char *ptr = strstr(ip_port, cc);
        if (ptr != NULL) {
            *ptr = ':';
            sprintf(cmd_buffer, "lsof -i @%s +c 0\n", ip_port);
        } else {
            printf("error: invalid ip format! %s\n", ip_port);
            return 1;
        }
    } else {
        // ipv6
        char *ptr = strstr(ip_port, cc);
        if (ptr != NULL) {
            *ptr = '\0';
            ptr++;
            sprintf(cmd_buffer, "lsof -i @[%s]:%s +c 0\n", ip_port, ptr);
        } else {
            printf("error: invalid ip format! %s\n", ip_port);
            return 1;
        }
    }
    printf("cmd buffer : %s\n", cmd_buffer);

    FILE *pipe = popen(cmd_buffer, "r");
    if (!pipe)
        return -1;
    while (!feof(pipe)) {
        if (fgets(buffer, 4096, pipe)) {
            printf("%s", buffer);
            strcat(result, buffer);
        }
    }
    pclose(pipe);
    return 0;
}

/*
 * call the ifconfig function to get the local ip setting
 * and put the result to the result buffer
 * */
int get_local_address(char *result){
    char * cmd_buffer = "ifconfig  | grep  'inet' | grep -v '127.0.0.1' | grep -v '<link>' | grep -v '<host>' | awk '{ print $2}'";
    char buffer [10240];

    FILE *pipe = popen(cmd_buffer, "r");
    if (!pipe)
        return -1;
    while (!feof(pipe)) {
        if (fgets(buffer, 1024, pipe)) {
            strcat(result, buffer);
        }
    }
    pclose(pipe);
    return 0;
}


/*
 * do not support change with the local ip
 * stop the thread if the ip is changed
 *
 * return 0 for is not local ip
 * */
int is_local_ip(char * ip_port_t){
    char * cc = "-";
    char ip_port [1024] = "";


    strcpy(ip_port,ip_port_t);
    char *ptr = strstr(ip_port, cc);
    *ptr = '\0';


    if (local_ip == NULL){
        char buffer [10240] = "";
        get_local_address(buffer);
        local_ip = (char *)malloc(sizeof(char) * strlen(buffer));
        strcpy(local_ip,buffer);
    }

    // if the ip is the substring of the local ip
    ptr = strstr(local_ip, ip_port);
    if (ptr != NULL){
        return 1;
    } else{
        return 0;
    }

}