//
// Created by sunxiao on 16/11/25.
//
#include <android/log.h>
#include <stdlib.h>
#include "jmnetworkprobe.h"
#include "dig_error.h"
#include "dig_data.h"
#include "dig.h"

static jobjectArray make_row(JNIEnv *env, jsize count, const char* elements[])
{
    jclass stringClass = (*env)->FindClass(env, "java/lang/String");
    jobjectArray row = (*env)->NewObjectArray(env, count, stringClass, 0);
    jsize i;
    
    for (i = 0; i < count; ++i)
    {
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "%s\n", elements[i]);
        (*env)->SetObjectArrayElement(env, row, i, (*env)->NewStringUTF(env, elements[i]));
    }
    return row;
}

JNIEXPORT jobjectArray JNICALL Java_com_jm_android_jmnetworkprobe_JMProbeManager_dig(JNIEnv *env, jobject obj,jstring host,jstring dnsIp)
{
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "dig begin");
    if(host == NULL || dnsIp == NULL)
    {
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "host or dns_ip is NULL");
        return NULL;
    }
    dig_message *dig_mess = create_dig_message();
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "create_dig_message");
    const char* host_char = (*env)->GetStringUTFChars(env,host,0);
    if(host_char == NULL)
    {
        clear_dig_message(dig_mess);
        return NULL;
    }
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "host_char:%s",host_char);
    const char* dns_char = (*env)->GetStringUTFChars(env,dnsIp,0);
    if(dns_char == NULL)
    {
        (*env)->ReleaseStringUTFChars(env,host,host_char);
        clear_dig_message(dig_mess);
        return NULL;
    }
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "dnsIp:%s",dns_char);
    
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "host:%s,dns_ip:%s",host_char,dns_char);
    
    int ret = get_dig_message(host_char, dns_char,dig_mess);
    if(ret != 0)
    {
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "get_dig_message return not zero,return:%d\n", ret);
        //清理资源
        (*env)->ReleaseStringUTFChars(env,host,host_char);
        (*env)->ReleaseStringUTFChars(env,dnsIp,dns_char);
        clear_dig_message(dig_mess);
        return NULL;
    }
    
    __android_log_print(ANDROID_LOG_ERROR, "DIG", "%d,%d,%d",dig_mess->answer_section_len,dig_mess->authority_section_len,dig_mess->additional_section_len);
    
    //answer_section 部分的填充
    jobjectArray answer_array = NULL;
    if(dig_mess->answer_section_len!=0)
    {
        answer_array = make_row(env, dig_mess->answer_section_len, (const char**)dig_mess->answer_section);
    }else{
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "answer_section_len is zero");
    }
    
    //authority_section 部分填充
    jobjectArray authrity_array = NULL;
    if(dig_mess->authority_section_len!=0)
    {
        authrity_array = make_row(env, dig_mess->authority_section_len, (const char**)dig_mess->authority_section);
    }else{
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "authority_section_len is zero");
    }
    
    //additional_section 部分填充
    jobjectArray additional_array = NULL;
    if(dig_mess->additional_section_len!=0)
    {
        additional_array = make_row(env, dig_mess->additional_section_len, (const char **)dig_mess->additional_section);
    }else{
        __android_log_print(ANDROID_LOG_ERROR, "DIG", "additional_section_len is zero");
    }
    jobjectArray rows = NULL;
    if(answer_array!=NULL){
    	rows = (*env)->NewObjectArray(env, 3, (*env)->GetObjectClass(env, answer_array), 0);
    	(*env)->SetObjectArrayElement(env, rows, 0, answer_array);
    	(*env)->SetObjectArrayElement(env, rows, 1, authrity_array);
    	(*env)->SetObjectArrayElement(env, rows, 2, additional_array);
    }
    
    //清理资源
    (*env)->ReleaseStringUTFChars(env,host,host_char);
    (*env)->ReleaseStringUTFChars(env,dnsIp,dns_char);
    clear_dig_message(dig_mess);
    
    return rows;
}

JNIEXPORT jstring JNICALL Java_com_jm_android_jmnetworkprobe_JMProbeManager_getlocaldns(JNIEnv *env, jobject obj,jstring host,jstring dnsIp)
{
    if(host == NULL || dnsIp == NULL){
        return NULL;
    }
    jstring ret;
    
    const char* host_char = (*env)->GetStringUTFChars(env,host,0);
    const char* dns_char = (*env)->GetStringUTFChars(env,dnsIp,0);
    
    char *ret_localdns = get_localdns(host_char, dns_char);
    if(ret_localdns!=NULL)
    {
        ret = (*env)->NewStringUTF(env,ret_localdns);
    }
    (*env)->ReleaseStringUTFChars(env,host,host_char);
    (*env)->ReleaseStringUTFChars(env,dnsIp,dns_char);
    return ret;
}
