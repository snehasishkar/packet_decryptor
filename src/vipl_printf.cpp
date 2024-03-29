/**************************************************************
* Author: Snehasish Kar
* date: 15th Mar 2015
* Version: 1.0.00
* Description:
* Below code is used to handle printf(), fprintf()
* Input for the same is the message and the error_lvl
**************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../include/vipl_printf.h"

void vipl_printf(char message[],int32_t error_lvl,char file[],int32_t line)
{
   FILE *fp;
   int ret_stat;
   time_t t = time(NULL);
   struct tm tm = *localtime(&t);
   char timestamp[100]={0x00};
   sprintf(timestamp, "%d-%d-%d:%d:%d:%d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
   fflush(stdout);
   switch(error_lvl)
   {
     case 1: printf("%s [%s:%d] %s\n",timestamp, file,line,message);break;
     case 2: fp=fopen("/var/log/vipl_receiver.log","a+");
             fprintf(fp,"%s [%s:%d] %s\n",timestamp, file,line,message);
             fclose(fp);
             break;
     case 3: fprintf(stderr,"%s [%s:%d] %s\n",timestamp, file,line,message);
    	 	 fp=fopen("/var/log/vipl_wifiServ.log","a+");
             fprintf(fp,"%s [%s:%d] %s\n",timestamp, file,line,message);
             fclose(fp);
             break;
   }
   fflush(stdout);
}
