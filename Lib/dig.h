//
//  dig.h
//  mobile_network_probe
//
//  Created by sunxiao on 16/12/28.
//  Copyright © 2016年 sunxiao. All rights reserved.
//

#ifndef dig_h
#define dig_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dig_error.h"
#include "dig_data.h"

dig_message *create_dig_message();
int clear_dig_message(dig_message *message);

int get_dig_message(const char *host,const char *dns_ip,dig_message *message);
char *get_localdns(const char *host,const char *dns_ip);

#endif /* dig_h */
