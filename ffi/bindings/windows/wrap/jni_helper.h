#ifndef __JNI_HELPER_H__
#define __JNI_HELPER_H__

#pragma GCC diagnostic ignored "-Wunused-function"

/* Note that method IDs are cached in static local variables.  This is susceptible to
 race conditions, but that's OK because the operations are idempotent.  Note also that
 global references are created for the classes that created the method IDs.  This keeps the
 classes from getting unloaded which would invalidate the cached method IDs. */

/**
 * Help for using the #defines
 * 		RETURN_NULL_IF_EXCEPTION(env);
 * 			checks for an exception. returns null to allow it to be thrown.
 *
 * 		RETURN_NULL_IF_EXCEPTION_OR_NULL(env, p);
 * 			checks for an exception or NULL==p. returns null to allow it to be thrown.
 *
 * 		POP_AND_RETURN_NULL_IF_EXCEPTION(env);
 * 			checks for an exception. returns null to allow it to be thrown, also does a PopLocalFrame
 *
 * 		POP_AND_RETURN_NULL_IF_EXCEPTION(env, p);
 * 			checks for an exception or NULL==p. returns null to allow it to be thrown, also does a PopLocalFrame
 *
 * Accessing a class:
 *  	// Get the class and hang onto the classId, you'll need this reference.
 *		GET_CACHED_CLASS(env, inet4AddressClass);
 *		RETURN_NULL_IF_EXCEPTION_OR_NULL(inet4Clazz);
 *
 * Accessing a Object Method:
 * 		GET_CACHED_METHOD_ID(env, inet4ConstructorID);
 *		RETURN_NULL_IF_EXCEPTION_OR_NULL(env, inet4ConstructorID);
 *
 *	The Method is now stored in inet4ConstructorID, which is a global static with a GlobalReference.
 *	As such you can reuse it, or recall the same function from 2 threads and result in the same information.
 *
 */

#include <stdlib.h>

#ifdef JAVA_DEBUG_TYPEMAPS
#undef NDEBUG
#include <assert.h>
#endif /* JAVA_DEBUG_TYPEMAPS */

#define RETURN_IF_EXCEPTION(env) {\
        if ((*(env))->ExceptionCheck(env)) {\
            return;\
        }\
    }

#define RETURN_NULL_IF_EXCEPTION(env) {\
        if ((*(env))->ExceptionCheck(env)) {\
            return 0;\
        }\
    }

#define RETURN_NULL_IF_CLASS_IS_NULL(env, p) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return NULL;\
    }\
    if (NULL == p) {\
       throw_null_pointer_exception(env, "class was not found "#p);\
       return 0;\
    }\
}

#define RETURN_IF_CLASS_IS_NULL(env, p) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return;\
    }\
    if (NULL == p) {\
        throw_null_pointer_exception(env, "class was not found "#p);\
        return;\
    }\
}

#define RETURN_NULL_IF_EXCEPTION_OR_NULL(env, p) {\
    if (NULL == p || (*(env))->ExceptionCheck(env)) {\
        return 0;\
    }\
}

#define RETURN_NULL_IF_EXCEPTION_OR_NULL_AND_FREE(env, p, func, context) {\
    if (NULL == p || (*(env))->ExceptionCheck(env)) {\
        if (NULL != context) { \
            (*func)(context); \
        } \
        return 0; \
    } \
}

#define POP_AND_RETURN_NULL_IF_EXCEPTION(env) {\
    if ((*(env))->ExceptionCheck(env)) {\
        (*(env))->PopLocalFrame(env, NULL);\
        return 0;\
    }\
}

#define POP_AND_RETURN_NULL_IF_EXCEPTION_OR_NULL(env, p) {\
    if (NULL == p || (*(env))->ExceptionCheck(env)) {\
       (*(env))->PopLocalFrame(env, NULL);\
       return 0;\
    }\
}

#define RETURN_NULL_IF_NOT_0_OR_EXCEPTION(env, p) {\
    if (0 != p || (*(env))->ExceptionCheck(env)) {\
        return 0;\
    }\
}

#define RETURN_IF_EXCEPTION_OR_NULL(env, p) {\
    if (0 == p || (*(env))->ExceptionCheck(env)) {\
        return;\
    }\
}

#define RETURN_NULL_IF_0_OR_EXCEPTION(env, p) {\
    if (0 == p || (*(env))->ExceptionCheck(env)) {\
        return 0;\
    }\
}

#define RETURN_NULL_AND_THROW_IF_NULL(env, p, mesg) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return 0;\
    }\
    if (0==p) {\
        throw_null_pointer_exception(env, mesg);\
        return 0;\
    }\
}

#define RETURN_FALSE_AND_THROW_IF_NULL(env, p, mesg) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return JNI_FALSE;\
    }\
    if (0==p) {\
        throw_null_pointer_exception(env, mesg);\
       return JNI_FALSE;\
    }\
}

#define RETURN_AND_THROW_IF_NULL(env, p, mesg) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return;\
    }\
    if (0==p) {\
        throw_null_pointer_exception(env, mesg);\
        return;\
    }\
}

#define RETURN_AND_THROW_IF_NOT_ZERO(env, p, mesg) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return;\
    }\
    if (0!=p) {\
        throw_exception(env, RUNTIME_EXCEPTION, mesg);\
        return;\
    }\
}

#define RETURN_FALSE_IF_EXCEPTION(env) {\
    if ((*(env))->ExceptionCheck(env)) {\
        return false;\
    }\
}

#define RETURN_FALSE_IF_EXCEPTION_OR_NULL(env, p) {\
    if (NULL == p || (*(env))->ExceptionCheck(env)) {\
        return false;\
    }\
}

#define RETURN_NULL_AND_THROW_IF_NOT_INSTANCEOF(env, object, clazz, mesg) {\
    if (JNI_FALSE == (*(env))->IsInstanceOf(env, object, clazz)) {\
        throw_exception(env, CLASS_CAST_EXCEPTION , mesg#clazz);\
        return 0;\
    }\
}

#define RETURN_AND_THROW_IF_NOT_INSTANCEOF(object, clazz, mesg) {\
    if (JNI_FALSE == (*(env))->IsInstanceOf(env, object, clazz)) {\
        throw_exception(env, CLASS_CAST_EXCEPTION , mesg#clazz);\
        return;\
    }\
}

#define DECLARE_CACHED_CLASS(class_var, class_name) \
static jclass class_var = 0; \
\
static jclass get_ ## class_var(JNIEnv *env) { \
    if (class_var) return class_var; \
    jclass clazz = (*(env))->FindClass(env, class_name); \
    if (0 == clazz) return 0; \
    clazz = (jclass) (*(env))->NewGlobalRef(env, clazz); \
    if (0 == clazz) return 0; \
    class_var = clazz; \
    return class_var; \
}

#define GET_CACHED_CLASS(env, class_var) get_##class_var(env)

#define DECLARE_CACHED_METHOD_ID(class_var, method_var, method_name, method_sig) \
static jmethodID method_var = 0; \
\
static jmethodID get_ ## method_var(JNIEnv *env) { \
    if (method_var) return method_var; \
    jclass clazz = GET_CACHED_CLASS(env, class_var); \
    if (0 == clazz) return 0; \
    method_var = (*(env))->GetMethodID(env, clazz, method_name, method_sig); \
    if ((*(env))->ExceptionCheck(env)) return 0; \
    return method_var; \
}

#define GET_CACHED_METHOD_ID(env, method_var) get_##method_var(env)

#define DECLARE_CACHED_STATIC_METHOD_ID(class_var, method_var, method_name, method_sig) \
static jmethodID method_var = 0; \
\
static jmethodID get_ ## method_var(JNIEnv *env) { \
    if (method_var) return method_var; \
    jclass clazz = GET_CACHED_CLASS(env, class_var); \
    if (0 == clazz) return 0; \
    method_var = (*(env))->GetStaticMethodID(env, clazz, method_name, method_sig); \
    if ((*(env))->ExceptionCheck(env)) return 0; \
    return method_var; \
}

#define GET_CACHED_STATIC_METHOD_ID(env, method_var) get_##method_var(env)

#define DECLARE_CACHED_FIELD_ID(class_var, fieldid_var, fieldid_name, fieldid_type) \
static jfieldID fieldid_var = 0; \
\
static jfieldID get_ ## fieldid_var(JNIEnv *env) { \
    if (fieldid_var) return fieldid_var; \
    jclass clazz = GET_CACHED_CLASS(env, class_var); \
    if (0 == clazz) return 0; \
    fieldid_var = (*(env))->GetFieldID(env, clazz, fieldid_name, fieldid_type); \
    if ((*(env))->ExceptionCheck(env)) return 0; \
    return fieldid_var; \
}

#define GET_CACHED_FIELD_ID(env, fieldid_var) get_##fieldid_var(env)

#define DECLARE_CACHED_STATIC_FIELD_ID(class_var, fieldid_var, fieldid_name, fieldid_type) \
static jfieldID fieldid_var = 0; \
\
static jfieldID get_ ## fieldid_var(JNIEnv *env) { \
    if (fieldid_var) return fieldid_var; \
    jclass clazz = GET_CACHED_CLASS(env, class_var); \
    if (0 == clazz) return 0; \
    fieldid_var = (*(env))->GetStaticFieldID(env, clazz, fieldid_name, fieldid_type); \
    if ((*(env))->ExceptionCheck(env)) return 0; \
    return fieldid_var; \
}

#define GET_CACHED_STATIC_FIELD_ID(env, fieldid_var) get_##fieldid_var(env)

DECLARE_CACHED_CLASS(stringBufferClass, "java/lang/StringBuffer")
DECLARE_CACHED_METHOD_ID(stringBufferClass, stringBufferCapacityID, "capacity",
        "()I")
DECLARE_CACHED_METHOD_ID(stringBufferClass, stringBufferSetLengthID,
        "setLength", "(I)V")
DECLARE_CACHED_METHOD_ID(stringBufferClass, stringBufferAppendStringID,
        "append", "(Ljava/lang/String;)Ljava/lang/StringBuffer;")
DECLARE_CACHED_METHOD_ID(stringBufferClass, stringBufferToStringID, "toString",
        "()Ljava/lang/String;")

DECLARE_CACHED_CLASS(stringClass, "java/lang/String")

#define OUT_OF_MEMORY_ERROR "java/lang/OutOfMemoryError"
#define IO_EXCEPTION "java/io/IOException"
#define RUNTIME_EXCEPTION "java/lang/RuntimeException"
#define INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/IndexOutOfBoundsException"
#define ARITHMETIC_EXCEPTION "java/lang/ArithmeticException"
#define ILLEGAL_ARGUMENT_EXCEPTION "java/lang/IllegalArgumentException"
#define NULL_POINTER_EXCEPTION "java/lang/NullPointerException"
#define UNKNOWN_HOST_EXCEPTION "java/net/UnknownHostException"
#define UNSUPPORTED_ENCODING_EXCEPTION "java/io/UnsupportedEncodingException"
#define CLASS_CAST_EXCEPTION "java/lang/ClassCastException"

static void throw_exception(JNIEnv *env, const char *exceptionClass,
        const char *message) {
    jclass clazz = 0;

    if (!env || !exceptionClass) {
        return;
    }

    (*(env))->ExceptionClear(env);

    clazz = (*(env))->FindClass(env, exceptionClass);

    if (0 == clazz) {
        fprintf(stderr, "Error, cannot find exception class: %s",
                exceptionClass);
        return;
    }

    (*(env))->ThrowNew(env, clazz, message);
}

static void throw_null_pointer_exception(JNIEnv *env, const char *mesg) {
    throw_exception(env, NULL_POINTER_EXCEPTION, mesg);
}

#endif /* __JNI_HELPER_H__ */
