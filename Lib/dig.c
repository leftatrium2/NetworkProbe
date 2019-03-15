#include "dig.h"
#include "dns.h"
#define LINE_MAX 80

dig_message *create_dig_message()
{
    dig_message *message = malloc(sizeof(dig_message));
    memset(message, 0, sizeof(dig_message));
    return message;
}

int clear_dig_message(dig_message *message)
{
    if(message!=NULL)
    {
        for(int i=0;i<MAX_MESSAGE_ITEM_LEN;i++)
        {
            free(message->additional_section[i]);
        }
        for(int i=0;i<MAX_MESSAGE_ITEM_LEN;i++)
        {
            free(message->answer_section[i]);
        }
        for(int i=0;i<MAX_MESSAGE_ITEM_LEN;i++)
        {
            free(message->authority_section[i]);
        }
    }
    return 0;
}

int get_dig_message(const char *host,const char *dns_ip,dig_message *message)
{
    if(dns_ip == NULL || strlen(dns_ip) == 0){
        return DIG_ERROR_DNS_IP_NULL;
    }
    
    int ret = get_host_by_name(host, dns_ip, message);
    
    return ret;
}

char *get_localdns(const char *host,const char *dns_ip)
{
    return get_localdns_by_name(host,dns_ip);
}
