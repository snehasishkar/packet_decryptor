/*
 * main.cpp
 *
 *  Created on: 20-May-2019
 *      Author: saurabh
 */

#include <iostream>
#include <string>
#include <queue>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <boost/thread.hpp>
#include <semaphore.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <boost/thread.hpp>
#include <chrono>
#include <ctime>
#include <pwd.h>
#include <sys/inotify.h>
#include "../include/vipl_printf.h"
#include "../include/decrypt_packet.h"
#include "../include/config4cpp/Configuration.h"

using namespace config4cpp;
using namespace std;

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

int32_t error_lvl = 0x00;

void parse_configfile(struct access_point** ap, int32_t *length){
	const char *default_configFile = "../config/vipl_ap_config.cfg";
	const char *scope = "";
	Configuration *  cfg = Configuration::create();
	StringBuffer filter, m_scope;
	StringVector scopes;
	m_scope = scope;
	Configuration::mergeNames(scope, "uid-ssid", filter);
	try{
		cfg->parse(default_configFile);
		cfg->listFullyScopedNames(m_scope.c_str(), "", Configuration::CFG_SCOPE, false, filter.c_str(), scopes);
		int len = scopes.length();
		*length = len;
		*ap = new struct access_point[len];
		for(int32_t i=0; i<len; i++){
			char *scope = new char(20);
			strcpy(scope, scopes[i]);
			strcpy((*ap)[i].essid, cfg->lookupString(scope, "essid"));
			strcpy((*ap)[i].password, cfg->lookupString(scope, "password"));
		}
	}catch(const ConfigurationException &e){
		char msg[100]={0x00};
		sprintf(msg,"warning: problem detected while reading config file %s",e.c_str());
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
	}
	cfg->destroy();
}
int main(int32_t argc, char **argv){
	struct access_point *ap=NULL;
	int32_t len=0;
	int32_t opt = 0x00;
	while((opt = getopt(argc, argv, "e:"))!= -1) {
		switch(opt){
	        case 'e': sscanf(optarg, "%d", &error_lvl);
	        	 	  break;
	        default: exit(EXIT_FAILURE);
	            	  break;
	    }
	}
	int32_t fd, wd, i=0, length=0;
	char buffer_event[EVENT_BUF_LEN];
    const char *homedir;
    char pcap_filename[200]={0x00}, dir_name[200]={0x00};
    if((homedir = getenv("HOME"))==NULL)
    	homedir = getpwuid(getuid())->pw_dir;
    bzero(dir_name, 200);
    sprintf(dir_name, "%s/wpcap_temp", homedir);
    parse_configfile(&ap, &len);
    fd = inotify_init ();
    if(fd < 0)
        vipl_printf("error: in inotify_init", error_lvl, __FILE__, __LINE__);
    while(true){
        wd = inotify_add_watch(fd, dir_name, IN_MOVED_TO);
        length = read(fd, buffer_event, EVENT_BUF_LEN);
        if(length<0)
      	  vipl_printf("error: in read", error_lvl, __FILE__, __LINE__);
        i=0;
        while(i<length){
      	  struct inotify_event *event = (struct inotify_event *) &buffer_event[i];
      	  if(event->len){
      		  if(event->mask & IN_MOVED_TO){
      			  bzero(pcap_filename, 200);
      			  sprintf(pcap_filename, "%s/%s", dir_name, event->name);
      		  }
      	  }
      	  i += EVENT_SIZE + event->len;
        }
        decrypt_packet(ap, len, pcap_filename, homedir);
    }
	return 0;
}
