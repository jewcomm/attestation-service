global-incdirs-y += include
LOCAL_PATH := $(call my-dir)
incdirs-y += $(LOCAL_PATH)../../../optee_os/core/include
srcs-y += attestation_service_ta.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
