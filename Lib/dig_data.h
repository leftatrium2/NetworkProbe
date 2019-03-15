//
//  dig_data.h
//  mobile_network_probe
//
//  Created by sunxiao on 16/12/30.
//  Copyright © 2016年 sunxiao. All rights reserved.
//

#ifndef dig_data_h
#define dig_data_h

#define MAX_MESSAGE_ITEM_LEN 30

#include "stdint.h"

typedef struct _dig_message{
    char *answer_section[MAX_MESSAGE_ITEM_LEN];
    uint8_t answer_section_len;
    char *authority_section[MAX_MESSAGE_ITEM_LEN];
    uint8_t authority_section_len;
    char *additional_section[MAX_MESSAGE_ITEM_LEN];
    uint8_t additional_section_len;
} dig_message;


#endif /* dig_data_h */
