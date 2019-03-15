LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := network_dig
LOCAL_SRC_FILES := \
jmnetworkprobe.c \
../../Lib/dig.c \
../../Lib/dns.c

TARGET_PLATFORM := android-25
LOCAL_C_INCLUDES := ../../Lib/
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
