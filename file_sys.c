//
// Created by lee yu on 2018/3/22.
//

#include "file_sys.h"
#include "time.h"
#include "stdio.h"


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