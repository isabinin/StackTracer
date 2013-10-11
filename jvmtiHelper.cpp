#include "stdafx.h"

#include <stdlib.h>

#include "jvmtiHelper.h"

void fatal_error(const char * format, ...) {
	va_list ap;

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	(void) fflush(stderr);
	va_end(ap);
	exit(3);
}

void check_jvmti_error(jvmtiEnv *jvmti, jvmtiError errnum,
		const char *str) {
	if (errnum != JVMTI_ERROR_NONE) {
		char *errnum_str;

		errnum_str = NULL;
		jvmti->GetErrorName(errnum, &errnum_str);

		fatal_error("ERROR: JVMTI: %d(%s): %s\n", errnum,
				(errnum_str == NULL ? "Unknown" : errnum_str),
				(str == NULL ? "" : str));
	}
}

void describe(jvmtiEnv *jvmti, jvmtiError err) {
	jvmtiError err0;
	char *descr;
	err0 = jvmti->GetErrorName(err, &descr);
	if (err0 == JVMTI_ERROR_NONE) {
		printf(descr);
	} else {
		printf("error [%d]", err);
	}
}

/* Enter raw monitor */
void menter(jvmtiEnv *jvmti, jrawMonitorID rmon) {
	jvmtiError err;

	err = jvmti->RawMonitorEnter(rmon);
	check_jvmti_error(jvmti, err, "raw monitor enter");
}

/* Exit raw monitor */
void mexit(jvmtiEnv *jvmti, jrawMonitorID rmon) {
	jvmtiError err;

	err = jvmti->RawMonitorExit(rmon);
	check_jvmti_error(jvmti, err, "raw monitor exit");
}

