//
//  通过UDP方式获取dns resulve信息
//
//  Created by sunxiao on 16/12/30.
//  Copyright © 2016年 sunxiao. All rights reserved.
//

#ifndef dns_h
#define dns_h

#include<stdio.h> //printf
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid
#include "dig_data.h"

//获取dns信息
//@param host 域名
int get_host_by_name(const char *host,const char *dns_ip,dig_message *message);
char *get_localdns_by_name(const char *host,const char *dns_ip);

#endif /* dns_h */
