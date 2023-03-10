#if SWIGJAVA

%rename("%(lowercamelcase)s") "";
%rename("Telio") "telio";

%{
#include "jni_helper.h"
#define PKG "com/nordsec/telio/"
static JavaVM *jvm = NULL;
%}

///////////////////////////////////////////////////////////////
// Wrap telio_event_cb into java interface

// ITelioEventCb.java is manualy written.
%typemap(jstype) telio_event_cb "ITelioEventCb"
%typemap(jtype) telio_event_cb "ITelioEventCb"
%typemap(jni) telio_event_cb "jobject"
%typemap(javain) telio_event_cb "$javainput"

%extend telio {

#if defined(__ANDROID__)
    telio(const char* features, telio_event_cb events, enum telio_log_level level, telio_logger_cb logger, telio_protect_cb protect) {
        telio *t;
        JNIEnv *env = NULL;
        if ((*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6)) {
            exit(1);
        }

        enum telio_result result;
        if ((result = telio_new_with_protect(&t, features, events, level, logger, protect)) != TELIO_RES_OK) {
            SWIG_JavaThrowException(env, SWIG_JavaIllegalArgumentException, "Failed to initiate telio");
            return NULL;
        }

        return t;
    }
#else
    telio(const char* features, telio_event_cb events, enum telio_log_level level, telio_logger_cb logger) {
        telio *t;
        JNIEnv *env = NULL;
        if ((*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6)) {
            exit(1);
        }

        enum telio_result result;
        if ((result = telio_new(&t, features, events, level, logger)) != TELIO_RES_OK) {
            SWIG_JavaThrowException(env, SWIG_JavaIllegalArgumentException, "Failed to initiate telio");
            return NULL;
        }

        return t;
    }
#endif
}

%{
DECLARE_CACHED_CLASS(iTelioEventCb, PKG "ITelioEventCb");
DECLARE_CACHED_METHOD_ID(iTelioEventCb, iTelioEventCbeventHandleID, "eventHandle", "(Ljava/lang/String;)V");

static void telio_jni_call_event_cb(void *ctx, const char *str) {
    if (!jvm) {
        return;
    }
    JNIEnv *env = NULL;
    
    jint res = (*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6);
    int attached = 0;
    if (JNI_EDETACHED == res) {
        JavaVMAttachArgs args = {
            .version = JNI_VERSION_1_6,
            .name = NULL,
            .group = NULL,
        };

        if ((*jvm)->AttachCurrentThread(jvm, &env, (void*)&args)) {
            return;
        }
        attached = 1;
    } else if (JNI_OK != res) {
        return;
    }

    jmethodID handle = GET_CACHED_METHOD_ID(env, iTelioEventCbeventHandleID);
    RETURN_AND_THROW_IF_NULL(env, handle, "eventHandle method not found.");

    jstring jstr = (*env)->NewStringUTF(env, str);
    RETURN_AND_THROW_IF_NULL(env, jstr, "Event string is null.");

    (*env)->CallVoidMethod(env, (jobject)ctx, handle, jstr);
    (*env)->DeleteLocalRef(env, jstr);
    if (attached) {
        (*jvm)->DetachCurrentThread(jvm);
    }
}
%}

// TODO: Add destructor for callback.
%typemap(in) telio_event_cb {
    if (!jvm) {
        (*jenv)->GetJavaVM(jenv, &jvm);
    }

    telio_event_cb cb = {
        .ctx = (*jenv)->NewGlobalRef(jenv, $input),
        .cb = telio_jni_call_event_cb,
    };

    $1 = cb;
}

///////////////////////////////////////////////////////////////
// Wrap telio_logger_cb into java interface

// ITelioLoggerCb.java is manualy written.
%typemap(jstype) telio_logger_cb "ITelioLoggerCb"
%typemap(jtype) telio_logger_cb "ITelioLoggerCb"
%typemap(jni) telio_logger_cb "jobject"
%typemap(javain) telio_logger_cb "$javainput"

%{
DECLARE_CACHED_CLASS(telioLogLevel, PKG "TelioLogLevel");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelCritical, "LOG_CRITICAL", "L" PKG "TelioLogLevel;");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelError,    "LOG_ERROR", "L" PKG "TelioLogLevel;");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelWarning,  "LOG_WARNING", "L" PKG "TelioLogLevel;");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelInfo,     "LOG_INFO", "L" PKG "TelioLogLevel;");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelDebug,    "LOG_DEBUG", "L" PKG "TelioLogLevel;");
DECLARE_CACHED_STATIC_FIELD_ID(telioLogLevel, jLogLevelTrace,    "LOG_TRACE", "L" PKG "TelioLogLevel;");


DECLARE_CACHED_CLASS(iTelioLoggerCb, PKG "ITelioLoggerCb");
DECLARE_CACHED_METHOD_ID(iTelioLoggerCb, iTelioLoggerCbloggerHandleID, "loggerHandle", "(L" PKG "TelioLogLevel;Ljava/lang/String;)V");

static void telio_jni_call_logger_cb(void *ctx, enum telio_log_level level, const char *str) {
    if (!jvm) {
        return;
    }

    JNIEnv *env = NULL;

    jint res = (*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6);
    int attached = 0;
    if (JNI_EDETACHED == res) {
        JavaVMAttachArgs args = {
            .version = JNI_VERSION_1_6,
            .name = NULL,
            .group = NULL,
        };

        if ((*jvm)->AttachCurrentThread(jvm, &env, (void*)&args)) {
            return;
        }
        attached = 1;
    } else if (JNI_OK != res) {
        return;
    }

    jmethodID handle = GET_CACHED_METHOD_ID(env, iTelioLoggerCbloggerHandleID);
    RETURN_AND_THROW_IF_NULL(env, handle, "loggerHandle not found.");

    jstring jstr = (*env)->NewStringUTF(env, str);
    RETURN_AND_THROW_IF_NULL(env, jstr, "Cannot crate log string.");

    jfieldID lfid = NULL;
    jclass jlevelClass = GET_CACHED_CLASS(env, telioLogLevel);
    RETURN_AND_THROW_IF_NULL(env, jlevelClass, "could not find TelioLogLevel class .");
    jobject jlevel = NULL;
    #define MAP(level, field) \
        case level:\
            lfid = GET_CACHED_STATIC_FIELD_ID(env, field);\
            RETURN_AND_THROW_IF_NULL(env, lfid, #level " level class not found.")\
            jlevel = (*env)->GetStaticObjectField(env, jlevelClass, lfid);\
            RETURN_AND_THROW_IF_NULL(env, jlevel, #level " level class not found.")\
            break;
    switch (level) {
        MAP(TELIO_LOG_CRITICAL, jLogLevelCritical)
        MAP(TELIO_LOG_ERROR, jLogLevelError)
        MAP(TELIO_LOG_WARNING, jLogLevelWarning)
        MAP(TELIO_LOG_INFO, jLogLevelInfo)
        MAP(TELIO_LOG_DEBUG, jLogLevelDebug)
        MAP(TELIO_LOG_TRACE, jLogLevelTrace)
    }
    #undef MAP

    (*env)->CallVoidMethod(env, (jobject)ctx, handle, jlevel, jstr);
    (*env)->DeleteLocalRef(env, jlevel);
    (*env)->DeleteLocalRef(env, jstr);
    if (attached) {
        (*jvm)->DetachCurrentThread(jvm);
    }
}
%}

%typemap(in) telio_logger_cb {
    if (!jvm) {
        (*jenv)->GetJavaVM(jenv, &jvm);
    }
    telio_logger_cb cb = {
        .ctx = (*jenv)->NewGlobalRef(jenv, $input),
        .cb = telio_jni_call_logger_cb,
    };
    $1 = cb;
}

///////////////////////////////////////////////////////////////
// Wrap telio_protect_cb into java interface

// ITelioProtectCb.java is manualy written.
%typemap(jstype) telio_protect_cb "ITelioProtectCb"
%typemap(jtype) telio_protect_cb "ITelioProtectCb"
%typemap(jni) telio_protect_cb "jobject"
%typemap(javain) telio_protect_cb "$javainput"

%{
DECLARE_CACHED_CLASS(iTelioProtectCb, PKG "ITelioProtectCb");
DECLARE_CACHED_METHOD_ID(iTelioProtectCb, iTelioProtectCbprotectHandleID, "protectHandle", "(I)V");

static void telio_jni_call_protect_cb(void *ctx, int fd) {
    if (!jvm) {
        return;
    }
    JNIEnv *env = NULL;
    
    jint res = (*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6);
    int attached = 0;
    if (JNI_EDETACHED == res) {
        JavaVMAttachArgs args = {
            .version = JNI_VERSION_1_6,
            .name = NULL,
            .group = NULL,
        };

        if ((*jvm)->AttachCurrentThread(jvm, &env, (void*)&args)) {
            return;
        }
        attached = 1;
    } else if (JNI_OK != res) {
        return;
    }

    jmethodID handle = GET_CACHED_METHOD_ID(env, iTelioProtectCbprotectHandleID);
    RETURN_AND_THROW_IF_NULL(env, handle, "eventHandle method not found.");

    (*env)->CallVoidMethod(env, (jobject)ctx, handle, fd);

    if (attached) {
        (*jvm)->DetachCurrentThread(jvm);
    }
}
%}

%typemap(in) telio_protect_cb {
    if (!jvm) {
        (*jenv)->GetJavaVM(jenv, &jvm);
    }
    telio_protect_cb cb = {
        .ctx = (*jenv)->NewGlobalRef(jenv, $input),
        .cb = telio_jni_call_protect_cb,
    };
    $1 = cb;
}

%{
jint JNI_OnLoad(JavaVM *jvm, void *reserved) {
    JNIEnv *env = NULL;
    jint res = (*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6);

    // FindClass will be called by a background thread, and it's not guaranteed that a non-main thread will find the class in question.
    // To ensure that class and method reference is cached, the first lookup is performed during jni initialization (by the main thread)
    GET_CACHED_METHOD_ID(env, iTelioLoggerCbloggerHandleID);
    GET_CACHED_METHOD_ID(env, iTelioEventCbeventHandleID);
    GET_CACHED_METHOD_ID(env, iTelioProtectCbprotectHandleID);
    GET_CACHED_CLASS(env, telioLogLevel);

    return JNI_VERSION_1_6;
}
%}

#endif

