#ifndef _JVMTI_HELPER_H
#define _JVMTI_HELPER_H

#include "jni.h"
#include "jvmti.h"

void fatal_error(const char * format, ...);

void check_jvmti_error(jvmtiEnv *jvmti, jvmtiError errnum, const char *str);

void describe(jvmtiEnv *jvmti, jvmtiError err);

/* Enter raw monitor */
void menter(jvmtiEnv *jvmti, jrawMonitorID rmon);

/* Exit raw monitor */
void mexit(jvmtiEnv *jvmti, jrawMonitorID rmon);

#endif /* _JVMTI_HELPER_H */
