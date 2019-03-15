//
//  dns.c
//  mobile_network_probe
//
//  Created by sunxiao on 16/12/30.
//  Copyright © 2016年 sunxiao. All rights reserved.
//
#include "dns.h"
#include "dig_error.h"


#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define TIMEOUT_SEC 10 //超时时间

#define MAX_CHAR_LEN 100

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
    
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
    
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
    
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

/*
 * This will convert www.google.com to 3www6google3com
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,const char* host)
{
    int lock = 0 , i;
    size_t len = strlen(host) + 10;
    char host2[len];
    bzero(host2, len);
    strcpy(host2, host);
    strcat(host2,".");
    
    for(i = 0 ; i < strlen((char*)host2) ; i++)
    {
        if(host2[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host2[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}


/*
 *
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
    
    *count = 1;
    name = (unsigned char*)malloc(256);
    
    name[0]='\0';
    
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
        
        reader = reader+1;
        
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
    
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
    
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

int get_host_by_name(const char *host,const char *dns_ip,dig_message *message)
{
    if(host == NULL || strlen(host) == 0){
        return DIG_ERROR_DNS_HOST_NULL;
    }
    if(dns_ip == NULL || strlen(dns_ip) == 0){
        return DIG_ERROR_DNS_IP_NULL;
    }
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
    
    struct sockaddr_in a;
    
    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
    
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
    if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))<0){
        //超时设置出错
        return DIG_ERROR_UDP_RECV_TIEMOUT;
    }
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_ip); //dns servers
    
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
    
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
    
    qinfo->qtype = htons( T_A ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
    
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        return DIG_ERROR_UDP_SEND;
    }
    
    //Receive the answer
    i = sizeof dest;
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        return DIG_ERROR_UDP_RECV;
    }
    
    dns = (struct DNS_HEADER*) buf;
    
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
    
    //Start reading answers
    stop=0;
    
    //answer
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
        
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
        
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
            
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
            
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
    
    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
        
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
        
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
    
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
        
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
        
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
                addit[i].rdata[j]=reader[j];
            
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }
    
    //print answers
    int ancount = ntohs(dns->ans_count);
    int answer_count = 0;
    char *temp;
    for(i=0 ; i < ancount ; i++)
    {
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(uint32_t)(*p); //working without ntohl
            temp = malloc(MAX_CHAR_LEN);
            bzero(temp, MAX_CHAR_LEN);
            snprintf(temp,MAX_CHAR_LEN,"%s IN A %s", answers[i].name,inet_ntoa(a.sin_addr));
            message->answer_section[i] = temp;
            answer_count++;
        } else if(ntohs(answers[i].resource->type)==T_CNAME)
        {
            //Canonical name for an alias
            temp = malloc(MAX_CHAR_LEN);
            bzero(temp, MAX_CHAR_LEN);
            snprintf(temp,MAX_CHAR_LEN,"%s IN CNAME %s", answers[i].name,answers[i].rdata);
            message->answer_section[i] = temp;
            answer_count++;
        }
    }
    message->answer_section_len = answer_count;
    
    //print authorities
    int aucount = ntohs(dns->auth_count);
    int authrity_count = 0;
    for( i=0 ; i < aucount ; i++)
    {
        long *p=(long*)auth[i].rdata;
        a.sin_addr.s_addr=(uint32_t)(*p);
        temp = malloc(MAX_CHAR_LEN);
        bzero(temp, MAX_CHAR_LEN);
        
        if(ntohs(auth[i].resource->type)==2)
        {
            snprintf(temp,MAX_CHAR_LEN,"%s IN NS %s",auth[i].name,auth[i].rdata);
        }
        message->authority_section[i] = temp;
        authrity_count++;
    }
    message->authority_section_len = authrity_count;
    
    //print additional resource records
    int adcount = ntohs(dns->add_count);
    int additional_count = 0;
    for(i=0; i < adcount ; i++)
    {
        if(ntohs(addit[i].resource->type)==1)
        {
            temp = malloc(MAX_CHAR_LEN);
            bzero(temp, MAX_CHAR_LEN);
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(uint32_t)(*p);
            snprintf(temp,MAX_CHAR_LEN,"%s IN A %s", addit[i].name,inet_ntoa(a.sin_addr));
            message->additional_section[i] = temp;
            additional_count++;
        }
    }
    message->additional_section_len = additional_count;
    return 0;
}

char *get_localdns_by_name(const char *host,const char *dns_ip)
{
    char *ret_chars = malloc(4 * 4 * sizeof(char));
    bzero(ret_chars, (4 * 4 * sizeof(char)));
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
    
    struct sockaddr_in a;
    
    struct RES_RECORD answers[20]; //the replies from the DNS server
    struct sockaddr_in dest;
    
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
    if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))<0){
        //超时设置出错
        return NULL;
    }
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_ip); //dns servers
    
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
    
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
    
    qinfo->qtype = htons( T_A ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
    
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        //发不出去，就不管了
        free(ret_chars);
        return NULL;
    }
    
    //Receive the answer
    i = sizeof dest;
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        //收不到，不管了
        free(ret_chars);
        return NULL;
    }
    
    dns = (struct DNS_HEADER*) buf;
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
    
    //Start reading answers
    stop=0;
    
    //answer
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
        
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
        
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
            
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
            
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
    
    //print answers
    int ancount = ntohs(dns->ans_count);
    for(i=0 ; i < ancount ; i++)
    {
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(uint32_t)(*p); //working without ntohl
            sprintf(ret_chars, "%s",inet_ntoa(a.sin_addr));
        }
    }
    return ret_chars;
}
