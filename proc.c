//
// Created by lee yu on 2018/4/2.
//


/*
 * created in order to call lsof to get the process details at the moment of the file is being created
 * */

#include "proc.h"
#include <stdio.h>
#include <string.h>
//#include "khash.h"
//#include "pthread.h"

//KHASH_SET_INIT_STR(data_file)
//int proc() {
//    int ret, is_missing;
//    khiter_t k;
//    khash_t(data_file) *h = kh_init(data_file);
//    k = kh_put(data_file, h, 5, &ret);
//
//    kh_value(h, k) = 10;
//    k = kh_get(32, h, 10);
//    is_missing = (k == kh_end(h));
//    k = kh_get(32, h, 5);
//    kh_del(32, h, k);
//    for (k = kh_begin(h); k != kh_end(h); ++k)
//        if (kh_exist(h, k)) kh_value(h, k) = 1;
//    kh_destroy(32, h);
//    return 0;
//}


int cmd(char* cmd, char* result)
{
    char buffer[10240];
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return -1;
    while(!feof(pipe)) {
        if(fgets(buffer, 4096, pipe)){
            printf("%s\n",buffer);
            strcat(result, buffer);
        }
    }
    pclose(pipe);
    return 0;
}