// StackTracer.cpp : Defines the exported functions for the DLL application.
//

// Usage: -agentpath:C:/Hackathon/StackTracer/x64/Debug/StackTracer64.dll

#include "stdafx.h"

#include <assert.h>

#include <io.h>
#include <stdio.h>

#include <string>

#include "jni.h"
#include "jvmti.h"

#include "jvmtiHelper.h"

static int versionNumber = 0x00000100;

static jrawMonitorID vm_death_lock;
static jboolean vm_death_active = JNI_TRUE;

#define MAX_STACK_FRAMES 4096
#define MAX_METHOD_ARGS_LENGTH 1024

static const char *jvmtiAgentLabel = "[StackTracer 0.1.0]";
static CRITICAL_SECTION *configuration_cs = NULL;

#define ARG_OPEN_BRACKET "("
#define ARG_CLOSE_BRACKET ") "

#define ENTER_CONFIG_CRITICAL_SECTION { EnterCriticalSection(configuration_cs); }
#define LEAVE_CONFIG_CRITICAL_SECTION { LeaveCriticalSection(configuration_cs); }

#define JNI_EXCEPTION_CHECK(ret)	\
	if (env->ExceptionCheck()) { \
		env->ExceptionClear(); \
		return ret; \
	}

#define JNI_EXCEPTION_HANDLE(ret)	\
	if (env->ExceptionCheck()) { \
		env->ExceptionClear(); \
		ret; \
	}

using namespace std;

/* All callbacks need to be extern "C" */
extern "C" {

static int snprintJString(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, char * buf, int maxChars, jstring string) {
	jsize methodNameLength = env->GetStringUTFLength(string);
	JNI_EXCEPTION_HANDLE(methodNameLength = 0);
	const char *chars = env->GetStringUTFChars(string, NULL);
	JNI_EXCEPTION_HANDLE(chars = NULL);
	if (chars != NULL) {
		int result = _snprintf(buf, maxChars, "\"%s\"", chars); 
		env->ReleaseStringUTFChars(string, chars);
		JNI_EXCEPTION_HANDLE();
		return result;
	}
	return 0;
}

#define PRINT_ELLIPSIS(buf, maxChars)	\
	buf[maxChars-4] = '.'; \
	buf[maxChars-3] = '.'; \
	buf[maxChars-2] = '.'; \
	buf[maxChars-1] = 0; \

#define PRINT_ARRAY_ELEMENTS(format, element)	\
		for (int i=0; i<length; i++) { \
			if (i > 0) { \
				result += _snprintf(buf + result, maxChars - result, ", "); \
				if (result>= maxChars) { \
					PRINT_ELLIPSIS(buf, maxChars) \
					break; \
				} \
			} \
			result += _snprintf(buf + result, maxChars - result, format, element); \
			if (result>= maxChars) { \
				PRINT_ELLIPSIS(buf, maxChars) \
				break; \
			} \
		}

int snprintJObject(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, char * buf, int maxChars, jobject object, char * signature);

static int snprintJArray(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, char * buf, int maxChars, jarray array, char * element_signature) {
	int result = _snprintf(buf, maxChars, "["); 
	int printed;

	jsize length = array != NULL ? env->GetArrayLength(array) : 0;
	JNI_EXCEPTION_HANDLE(length = NULL);
	if (length > 0) {
	switch(element_signature[0])
	{
	case 'B':// 	byte 	signed byte
	{
		jbyteArray byteArray = (jbyteArray) array;
		jbyte* elements = env->GetByteArrayElements(byteArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%d", (int) elements[i]);
		env->ReleaseByteArrayElements(byteArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'C':// 	char 	Unicode character
	{
		jcharArray charArray = (jcharArray) array;
		jchar* elements = env->GetCharArrayElements(charArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%d '%c'", (int) elements[i], (char) elements[i]);
		env->ReleaseCharArrayElements(charArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'S':// 	short 	signed short
	{
		jshortArray shortArray = (jshortArray) array;
		jshort* elements = env->GetShortArrayElements(shortArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%d", (int) elements[i]);
		env->ReleaseShortArrayElements(shortArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'I':// 	int 	integer
	{
		jintArray intArray = (jintArray) array;
		jint* elements = env->GetIntArrayElements(intArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%d", elements[i]);
		env->ReleaseIntArrayElements(intArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'Z':// 	boolean 	true or false
	{
		jbooleanArray booleanArray = (jbooleanArray) array;
		jboolean* elements = env->GetBooleanArrayElements(booleanArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%s", elements[i] ? "true" : "false");
		env->ReleaseBooleanArrayElements(booleanArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'D':// 	double 	double-precision floating-point value
	{
		jdoubleArray doubleArray = (jdoubleArray) array;
		jdouble* elements = env->GetDoubleArrayElements(doubleArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%g", elements[i]);
		env->ReleaseDoubleArrayElements(doubleArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'F':// 	float 	single-precision floating-point value
	{
		jfloatArray floatArray = (jfloatArray) array;
		jfloat* elements = env->GetFloatArrayElements(floatArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%g", elements[i]);
		env->ReleaseFloatArrayElements(floatArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'J':// 	long 	long integer
	{
		jlongArray longArray = (jlongArray) array;
		jlong* elements = env->GetLongArrayElements(longArray, NULL);
		JNI_EXCEPTION_HANDLE(length = 0);
		PRINT_ARRAY_ELEMENTS("%lld", elements[i]);
		env->ReleaseLongArrayElements(longArray, elements, JNI_ABORT);
		JNI_EXCEPTION_HANDLE();
		break;
	}
	case 'L'://		L<classname>; 	reference 	an instance of class <classname>
	case '[':// 	reference 	one array dimension
	{
		jobjectArray objectArray = (jobjectArray) array;
		for (jsize j=0; j<length; j++) {
			jobject value = env->GetObjectArrayElement(objectArray, j);
			JNI_EXCEPTION_HANDLE(value = NULL);
			for (int i=0; i<length; i++) {
				if (i > 0) {
					result += _snprintf(buf + result, maxChars - result, ", ");
					if (result>= maxChars) {
						PRINT_ELLIPSIS(buf, maxChars);
						break;
					}
				}
				result += snprintJObject(jvmti, env, thr, buf + result, maxChars - result, value, element_signature);
				if (result>= maxChars) {
					PRINT_ELLIPSIS(buf, maxChars);
					break;
				} \
			}
		}
		break;
	}
	default:
		fatal_error("Unsupported class signature \"%s\"", element_signature);
	} // switch
	}
	if (maxChars > result) {
		result += _snprintf(buf + result, maxChars - result, "]"); 
	}
	return result;
}

static int snprintJObject(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, char * buf, int maxChars, jobject object, char * signature) {
	if (object == NULL) {
		return _snprintf(buf, maxChars, "null"); 
	}
	if (strcmp("Ljava/lang/String;", signature) == 0) {
		return snprintJString(jvmti, env, thr, buf, maxChars, (jstring) object);
	} 
	if (signature[0] == '[') {
		return snprintJArray(jvmti, env, thr, buf, maxChars, (jarray) object, signature + 1);
	}

	int result = 0;
	jclass javaLangObject = env->FindClass("java/lang/Object");
	JNI_EXCEPTION_HANDLE(javaLangObject = NULL);
	jmethodID toString = javaLangObject != NULL ? env->GetMethodID(javaLangObject, "toString", "()Ljava/lang/String;") : NULL;
	JNI_EXCEPTION_HANDLE(toString = NULL);
	if (toString != NULL) {
		jstring string = (jstring) env->CallObjectMethod(object, toString);
		const char *stringChars = env->GetStringUTFChars(string, NULL);
		JNI_EXCEPTION_HANDLE(stringChars = NULL);
		result += _snprintf(buf, maxChars, stringChars);
		env->ReleaseStringUTFChars(string, stringChars);
	}

	jclass javaLangClass = env->FindClass("java/lang/Class");
	JNI_EXCEPTION_HANDLE(javaLangClass = NULL);
	jmethodID getClassName = javaLangClass != NULL ? env->GetMethodID(javaLangClass, "getName", "()Ljava/lang/String;") : NULL;
	JNI_EXCEPTION_HANDLE(getClassName = NULL);
	jclass klass = env->GetObjectClass(object);
	JNI_EXCEPTION_HANDLE(klass = NULL);
	if (getClassName != NULL && klass != NULL) {
		jstring className = (jstring) env->CallObjectMethod(klass, getClassName);
		const char *classNameChars = env->GetStringUTFChars(className, NULL);
		JNI_EXCEPTION_HANDLE(classNameChars = NULL);
		if (result > 0) {
			result += _snprintf(buf + result, maxChars, " ");
		}
		result += _snprintf(buf + result, maxChars, classNameChars);
		env->ReleaseStringUTFChars(className, classNameChars);
	}

	return result;
}

static int snprintVarValue(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, char * buf, int maxChars, jvmtiLocalVariableEntry * varInfo, jint frameIndex) {
	jvmtiError err;
	char * signature = varInfo->signature;
	switch(signature[0]) {
	case 'C':// 	char 	Unicode character
	{
		jint intValue = 0;
		err = jvmti->GetLocalInt(thr, frameIndex, varInfo->slot, &intValue);
		jchar value = (jchar) intValue;
		return _snprintf(buf, maxChars, "%d '%c'", intValue, value);
	}
	case 'B':// 	byte 	signed byte
	case 'S':// 	short 	signed short
	case 'I':// 	int 	integer
	{
		jint intValue = 0;
		err = jvmti->GetLocalInt(thr, frameIndex, varInfo->slot, &intValue);
		return _snprintf(buf, maxChars, "%d", intValue);
	}
	case 'Z':// 	boolean 	true or false
	{
		jint intValue = 0;
		err = jvmti->GetLocalInt(thr, frameIndex, varInfo->slot, &intValue);
		return _snprintf(buf, maxChars, intValue ? "true" : "false");
	}
	case 'D':// 	double 	double-precision floating-point value
	{
		jdouble value = 0;
		err = jvmti->GetLocalDouble(thr, frameIndex, varInfo->slot, &value);
		return _snprintf(buf, maxChars, "%g", value);
	}
	case 'F':// 	float 	single-precision floating-point value
	{
		jfloat value = 0;
		err = jvmti->GetLocalFloat(thr, frameIndex, varInfo->slot, &value);
		return _snprintf(buf, maxChars, "%g", value);
	}
	case 'J':// 	long 	long integer
	{
		jlong value = 0;
		err = jvmti->GetLocalLong(thr, frameIndex, varInfo->slot, &value);
		return _snprintf(buf, maxChars, "%lld", value);
	}
	case 'L'://		L<classname>; 	reference 	an instance of class <classname>
	case '[':// 	reference 	one array dimension
	{
		jobject value;
		err = jvmti->GetLocalObject(thr, frameIndex, varInfo->slot, &value);
		//return snprintJObject(jvmti, env, thr, buf, maxChars, value, signature);
		return 0;
	}
	default:
		fatal_error("Unsupported class signature \"%s\"", signature);
	} // switch
	return 0;
}

static char * addMethodArguments(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, const char *methodNameChars, jvmtiFrameInfo * frameInfo, jint frameIndex) {
	jint numArgs = 0;
	jvmtiError err = jvmti->GetArgumentsSize(frameInfo[frameIndex].method, &numArgs);
	if (err == JVMTI_ERROR_NATIVE_METHOD) {
		numArgs = -1;
	}
	if (numArgs > 0) {
		jint entry_count = 0;
		jvmtiLocalVariableEntry* var_table = NULL;
		err = jvmti->GetLocalVariableTable(frameInfo[frameIndex].method, &entry_count, &var_table);
		if (err == JVMTI_ERROR_NONE) {
			char *newMethodNameChars = NULL;
			int newMethodNameLength = 0;
			//int hasThis = 0;
			bool hasArgs = false;
			for (int i = 0; i < entry_count; i++) {
				if (var_table[i].start_location > frameInfo[frameIndex].location) {
					//Variable is not visible yet
					continue;
				}
				if (var_table[i].slot == 0 && strcmp("this", var_table[i].name) == 0) {
					//hasThis = 1;
					continue;
				}
				if (var_table[i].slot /*- hasThis*/ >= numArgs) {
					continue;
				}
				if (hasArgs) {
					newMethodNameChars[newMethodNameLength++] = ',';
					newMethodNameChars[newMethodNameLength++] = ' ';
				}
				else {
					int methodNameLength = strlen(methodNameChars);
					newMethodNameChars = new char[methodNameLength + MAX_METHOD_ARGS_LENGTH + 4];
					strncpy(newMethodNameChars, methodNameChars, methodNameLength);
					newMethodNameLength = methodNameLength;
					newMethodNameLength += _snprintf(newMethodNameChars + newMethodNameLength, MAX_METHOD_ARGS_LENGTH - newMethodNameLength, ARG_OPEN_BRACKET);
				}
				newMethodNameLength += snprintVarValue(jvmti, env, thr, newMethodNameChars + newMethodNameLength, MAX_METHOD_ARGS_LENGTH - newMethodNameLength, var_table + i, frameIndex);
				newMethodNameChars[newMethodNameLength] = 0;
				hasArgs = true;
			}
			for (jint i=0; i<entry_count; i++) {
				jvmti->Deallocate((unsigned char *)var_table[i].name);
				jvmti->Deallocate((unsigned char *)var_table[i].signature);
				jvmti->Deallocate((unsigned char *)var_table[i].generic_signature);
			}
			if (var_table != NULL) {
				jvmti->Deallocate((unsigned char *)var_table);
			}
			if (newMethodNameChars != NULL) {
				newMethodNameLength += _snprintf(newMethodNameChars + newMethodNameLength, MAX_METHOD_ARGS_LENGTH - newMethodNameLength, ARG_CLOSE_BRACKET);
				newMethodNameChars[newMethodNameLength] = 0;
				return newMethodNameChars;
			}
		}
	}
	return NULL;
}

// Exception callback
static void JNICALL callbackException(jvmtiEnv *jvmti, JNIEnv* env, jthread thr, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location) {
	ENTER_CONFIG_CRITICAL_SECTION
	menter(jvmti, vm_death_lock); {
		jvmtiError err;
		bool filtered = false;
		if (catch_method != NULL) {
			char *catchMethodName = NULL;
			char *catchDeclaringClassName = NULL;
			err = jvmti->GetMethodName(catch_method, &catchMethodName, NULL, NULL);
			if (err == JVMTI_ERROR_NONE) {
				jclass catchDeclaringClass;
				err = jvmti->GetMethodDeclaringClass(catch_method, &catchDeclaringClass);
				if (err == JVMTI_ERROR_NONE) {
					err = jvmti->GetClassSignature(catchDeclaringClass, &catchDeclaringClassName, NULL);
					if (err == JVMTI_ERROR_NONE) {
						if (strcmp(catchMethodName, "loadClass") == 0 && strcmp(catchDeclaringClassName, "Ljava/lang/ClassLoader;") == 0)
							filtered = true;
						else if (strncmp(catchDeclaringClassName, "Ljava", 5) == 0)
							filtered = true;
						else if (strncmp(catchDeclaringClassName, "Lsun", 4) == 0)
							filtered = true;
					}
				}
			}
			jvmti->Deallocate((unsigned char *)catchMethodName);
			jvmti->Deallocate((unsigned char *)catchDeclaringClassName);
		}

		if (!filtered) {
			jclass javaLangThrowable = env->FindClass("java/lang/Throwable");
			JNI_EXCEPTION_HANDLE(javaLangThrowable = NULL);
			jmethodID getOurStackTrace = javaLangThrowable != NULL ? env->GetMethodID(javaLangThrowable, "getOurStackTrace", "()[Ljava/lang/StackTraceElement;") : NULL;
			JNI_EXCEPTION_HANDLE(getOurStackTrace = NULL);

			jclass stackTraceElementClass = env->FindClass("java/lang/StackTraceElement");
			JNI_EXCEPTION_HANDLE(stackTraceElementClass = NULL);
			jfieldID methodNameField = stackTraceElementClass != NULL ? env->GetFieldID(stackTraceElementClass, "methodName", "Ljava/lang/String;") : NULL;
			JNI_EXCEPTION_HANDLE(methodNameField = NULL);

			if (getOurStackTrace != NULL && methodNameField != NULL) {
				jobjectArray stackTraceElements = (jobjectArray) env->CallObjectMethod(exception, getOurStackTrace);
				JNI_EXCEPTION_HANDLE(stackTraceElements = NULL);
				if (stackTraceElements != NULL) {
					jsize length = env->GetArrayLength(stackTraceElements);
					JNI_EXCEPTION_HANDLE(length = 0);

					//Get Stack Trace
					jvmtiFrameInfo *frames = new jvmtiFrameInfo[MAX_STACK_FRAMES];
					jint framesCount = 0;
					jvmtiError err = jvmti->GetStackTrace(thr, 0, MAX_STACK_FRAMES, frames, &framesCount);
					if (err == JVMTI_ERROR_NONE) {
						for (jsize j=0; j<length && j<framesCount; j++) {
							jobject stackTraceElement = env->GetObjectArrayElement(stackTraceElements, j);
							JNI_EXCEPTION_HANDLE(stackTraceElement = NULL);
							jobject methodName = env->GetObjectField(stackTraceElement, methodNameField);
							JNI_EXCEPTION_HANDLE(stackTraceElement = NULL);
							if (methodName != NULL) {
								jsize methodNameLength = env->GetStringUTFLength((jstring) methodName);
								JNI_EXCEPTION_HANDLE(methodNameLength = 0);
								const char *methodNameChars = env->GetStringUTFChars((jstring) methodName, NULL);
								JNI_EXCEPTION_HANDLE(methodNameChars = NULL);
								if (methodNameChars != NULL) {
									char *newMethodNameChars = addMethodArguments(jvmti, env, thr, methodNameChars, frames, j);
									if (newMethodNameChars != NULL) {
										jstring newMethodName = env->NewStringUTF(newMethodNameChars);
										JNI_EXCEPTION_HANDLE(newMethodName = NULL);
										env->SetObjectField(stackTraceElement, methodNameField, newMethodName);
										JNI_EXCEPTION_HANDLE();
										delete newMethodNameChars;
									}
									env->ReleaseStringUTFChars((jstring) methodName, methodNameChars);
									JNI_EXCEPTION_HANDLE();
								}
							}						
						}
					}
					delete frames;
				}
			}
		}
	} mexit(jvmti, vm_death_lock);
	  LEAVE_CONFIG_CRITICAL_SECTION
}

static string getJavaSystemProperty(JNIEnv *env, const char *propertyNameChars) {
	jclass systemClass = env->FindClass("java/lang/System");
	JNI_EXCEPTION_CHECK(NULL);
	jmethodID getProperty = env->GetStaticMethodID(systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
	JNI_EXCEPTION_CHECK(NULL);
	jstring propertyName = env->NewStringUTF(propertyNameChars);
	JNI_EXCEPTION_CHECK(NULL);
	jstring propertyValue = (jstring) env->CallStaticObjectMethod(systemClass, getProperty, propertyName);
	JNI_EXCEPTION_CHECK(NULL);
	const char *propertyValueChars = env->GetStringUTFChars((jstring) propertyValue, NULL);
	JNI_EXCEPTION_CHECK(NULL);
	string result(propertyValueChars);
	env->ReleaseStringUTFChars(propertyValue, propertyValueChars);
	JNI_EXCEPTION_CHECK(result);
	return result;
}

static void setJavaSystemProperty(JNIEnv *env, const char *propertyNameChars, const char *propertyValueChars) {
	jclass systemClass = env->FindClass("java/lang/System");
	JNI_EXCEPTION_CHECK();
	jmethodID setProperty = env->GetStaticMethodID(systemClass, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
	JNI_EXCEPTION_CHECK();
	jstring propertyName = env->NewStringUTF(propertyNameChars);
	JNI_EXCEPTION_CHECK();
	jstring propertyValue = env->NewStringUTF(propertyValueChars);
	JNI_EXCEPTION_CHECK();
	env->CallStaticObjectMethod(systemClass, setProperty, propertyName, propertyValue);
	JNI_EXCEPTION_CHECK();
}

static void JNICALL
vm_init(jvmtiEnv *jvmti, JNIEnv *env, jthread thread)
{
	jvmtiError err;
	//Agent     *agent;

	jint jvmtiVersion;
	err = jvmti->GetVersionNumber(&jvmtiVersion);
	check_jvmti_error(jvmti, err, "vm_init");

	fprintf(stderr, "%s JVMTI version %08x; %s; %s; %s; %s; %s\n", jvmtiAgentLabel, jvmtiVersion,
		getJavaSystemProperty(env, "java.vm.version").c_str(),
		getJavaSystemProperty(env, "java.vm.vendor").c_str(),
		getJavaSystemProperty(env, "java.vm.info").c_str(),
		getJavaSystemProperty(env, "os.name").c_str(),
		getJavaSystemProperty(env, "os.arch").c_str());
	fflush(stderr);

	// Initilize the critical section
	configuration_cs = new CRITICAL_SECTION();
	InitializeCriticalSection(configuration_cs);

	/* Create raw monitor to protect against threads running after death */
	err = jvmti->CreateRawMonitor("Waiters vm_death lock", &vm_death_lock);
	check_jvmti_error(jvmti, err, "create raw monitor");
	vm_death_active = JNI_FALSE;

	/* Create an Agent instance, set JVMTI Local Storage */
	//agent = new Agent(jvmti, env, thread);
	//err = jvmti->SetEnvironmentLocalStorage((const void*)agent);
	//check_jvmti_error(jvmti, err, "set env local storage");

	/* Enable all other events we want */
	err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
			JVMTI_EVENT_VM_DEATH, NULL);
	check_jvmti_error(jvmti, err, "vm_init");
	err = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
			JVMTI_EVENT_EXCEPTION, NULL);
	check_jvmti_error(jvmti, err, "vm_init");
}

static void JNICALL
vm_death(jvmtiEnv *jvmti, JNIEnv *env)
{
	if (configuration_cs != NULL) {
		DeleteCriticalSection(configuration_cs);
		delete configuration_cs;
		configuration_cs = NULL;
	}

	//jvmtiError err;
	//Agent     *agent;

	/* Block all callbacks */
	menter(jvmti, vm_death_lock); {
		/* Set flag for other callbacks */
		vm_death_active = JNI_TRUE;

		/* Inform Agent instance of VM_DEATH */
		//agent = get_agent(jvmti);
		//agent->vm_death(jvmti, env);

		/* Reclaim space of Agent */
		//err = jvmti->SetEnvironmentLocalStorage((const void*)NULL);
		//check_jvmti_error(jvmti, err, "set env local storage");
		//delete agent;
	}mexit(jvmti, vm_death_lock);

}

/* Agent_OnLoad() is called first */
JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *opts, void *reserved)
{
	//assert(0);

	jvmtiEnv *jvmti;
	jint rc;
	jvmtiError err;
	jvmtiCapabilities capabilities;
	jvmtiEventCallbacks callbacks;

	/* Get JVMTI environment */
	rc = vm->GetEnv((void **)&jvmti, JVMTI_VERSION);
	if (rc != JNI_OK) {
		fatal_error("ERROR: Unable to create jvmtiEnv, GetEnv failed, error=%d\n", rc);
		return -1;
	}

	/* Get/Add JVMTI capabilities */
	(void)memset(&capabilities, 0, sizeof(capabilities));
	capabilities.can_get_owned_monitor_info = 1;
	capabilities.can_generate_exception_events = 1;
	capabilities.can_access_local_variables = 1;
	capabilities.can_get_line_numbers = 1;
	capabilities.can_get_source_file_name = 1;
	err = jvmti->AddCapabilities(&capabilities);
	check_jvmti_error(jvmti, err, "add capabilities");

	/* Set all callbacks and enable VM_INIT event notification */
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.VMInit = &vm_init;
	callbacks.VMDeath = &vm_death;
	callbacks.Exception = &callbackException;/* JVMTI_EVENT_EXCEPTION */
	err = jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
	check_jvmti_error(jvmti, err, "set event callbacks");
	err = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
	check_jvmti_error(jvmti, err, "set event notify");

	return JNI_OK;
}
} // extern "C"
