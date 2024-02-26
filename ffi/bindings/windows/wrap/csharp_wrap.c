/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */


#ifndef SWIGCSHARP
#define SWIGCSHARP
#endif


/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if defined(__GNUC__)
#  if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#    ifndef GCC_HASCLASSVISIBILITY
#      define GCC_HASCLASSVISIBILITY
#    endif
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif

/* Deal with Apple's deprecated 'AssertMacros.h' from Carbon-framework */
#if defined(__APPLE__) && !defined(__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES)
# define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#endif

/* Intel's compiler complains if a variable which was never initialised is
 * cast to void, which is a common idiom which we use to indicate that we
 * are aware a variable isn't used.  So we just silence that warning.
 * See: https://github.com/swig/swig/issues/192 for more discussion.
 */
#ifdef __INTEL_COMPILER
# pragma warning disable 592
#endif


#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* Support for throwing C# exceptions from C/C++. There are two types: 
 * Exceptions that take a message and ArgumentExceptions that take a message and a parameter name. */
typedef enum {
  SWIG_CSharpApplicationException,
  SWIG_CSharpArithmeticException,
  SWIG_CSharpDivideByZeroException,
  SWIG_CSharpIndexOutOfRangeException,
  SWIG_CSharpInvalidCastException,
  SWIG_CSharpInvalidOperationException,
  SWIG_CSharpIOException,
  SWIG_CSharpNullReferenceException,
  SWIG_CSharpOutOfMemoryException,
  SWIG_CSharpOverflowException,
  SWIG_CSharpSystemException
} SWIG_CSharpExceptionCodes;

typedef enum {
  SWIG_CSharpArgumentException,
  SWIG_CSharpArgumentNullException,
  SWIG_CSharpArgumentOutOfRangeException
} SWIG_CSharpExceptionArgumentCodes;

typedef void (SWIGSTDCALL* SWIG_CSharpExceptionCallback_t)(const char *);
typedef void (SWIGSTDCALL* SWIG_CSharpExceptionArgumentCallback_t)(const char *, const char *);

typedef struct {
  SWIG_CSharpExceptionCodes code;
  SWIG_CSharpExceptionCallback_t callback;
} SWIG_CSharpException_t;

typedef struct {
  SWIG_CSharpExceptionArgumentCodes code;
  SWIG_CSharpExceptionArgumentCallback_t callback;
} SWIG_CSharpExceptionArgument_t;

static SWIG_CSharpException_t SWIG_csharp_exceptions[] = {
  { SWIG_CSharpApplicationException, NULL },
  { SWIG_CSharpArithmeticException, NULL },
  { SWIG_CSharpDivideByZeroException, NULL },
  { SWIG_CSharpIndexOutOfRangeException, NULL },
  { SWIG_CSharpInvalidCastException, NULL },
  { SWIG_CSharpInvalidOperationException, NULL },
  { SWIG_CSharpIOException, NULL },
  { SWIG_CSharpNullReferenceException, NULL },
  { SWIG_CSharpOutOfMemoryException, NULL },
  { SWIG_CSharpOverflowException, NULL },
  { SWIG_CSharpSystemException, NULL }
};

static SWIG_CSharpExceptionArgument_t SWIG_csharp_exceptions_argument[] = {
  { SWIG_CSharpArgumentException, NULL },
  { SWIG_CSharpArgumentNullException, NULL },
  { SWIG_CSharpArgumentOutOfRangeException, NULL }
};

static void SWIGUNUSED SWIG_CSharpSetPendingException(SWIG_CSharpExceptionCodes code, const char *msg) {
  SWIG_CSharpExceptionCallback_t callback = SWIG_csharp_exceptions[SWIG_CSharpApplicationException].callback;
  if ((size_t)code < sizeof(SWIG_csharp_exceptions)/sizeof(SWIG_CSharpException_t)) {
    callback = SWIG_csharp_exceptions[code].callback;
  }
  callback(msg);
}

static void SWIGUNUSED SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpExceptionArgumentCodes code, const char *msg, const char *param_name) {
  SWIG_CSharpExceptionArgumentCallback_t callback = SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentException].callback;
  if ((size_t)code < sizeof(SWIG_csharp_exceptions_argument)/sizeof(SWIG_CSharpExceptionArgument_t)) {
    callback = SWIG_csharp_exceptions_argument[code].callback;
  }
  callback(msg, param_name);
}


#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterExceptionCallbacks_libtelio(
                                                SWIG_CSharpExceptionCallback_t applicationCallback,
                                                SWIG_CSharpExceptionCallback_t arithmeticCallback,
                                                SWIG_CSharpExceptionCallback_t divideByZeroCallback, 
                                                SWIG_CSharpExceptionCallback_t indexOutOfRangeCallback, 
                                                SWIG_CSharpExceptionCallback_t invalidCastCallback,
                                                SWIG_CSharpExceptionCallback_t invalidOperationCallback,
                                                SWIG_CSharpExceptionCallback_t ioCallback,
                                                SWIG_CSharpExceptionCallback_t nullReferenceCallback,
                                                SWIG_CSharpExceptionCallback_t outOfMemoryCallback, 
                                                SWIG_CSharpExceptionCallback_t overflowCallback, 
                                                SWIG_CSharpExceptionCallback_t systemCallback) {
  SWIG_csharp_exceptions[SWIG_CSharpApplicationException].callback = applicationCallback;
  SWIG_csharp_exceptions[SWIG_CSharpArithmeticException].callback = arithmeticCallback;
  SWIG_csharp_exceptions[SWIG_CSharpDivideByZeroException].callback = divideByZeroCallback;
  SWIG_csharp_exceptions[SWIG_CSharpIndexOutOfRangeException].callback = indexOutOfRangeCallback;
  SWIG_csharp_exceptions[SWIG_CSharpInvalidCastException].callback = invalidCastCallback;
  SWIG_csharp_exceptions[SWIG_CSharpInvalidOperationException].callback = invalidOperationCallback;
  SWIG_csharp_exceptions[SWIG_CSharpIOException].callback = ioCallback;
  SWIG_csharp_exceptions[SWIG_CSharpNullReferenceException].callback = nullReferenceCallback;
  SWIG_csharp_exceptions[SWIG_CSharpOutOfMemoryException].callback = outOfMemoryCallback;
  SWIG_csharp_exceptions[SWIG_CSharpOverflowException].callback = overflowCallback;
  SWIG_csharp_exceptions[SWIG_CSharpSystemException].callback = systemCallback;
}

#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterExceptionArgumentCallbacks_libtelio(
                                                SWIG_CSharpExceptionArgumentCallback_t argumentCallback,
                                                SWIG_CSharpExceptionArgumentCallback_t argumentNullCallback,
                                                SWIG_CSharpExceptionArgumentCallback_t argumentOutOfRangeCallback) {
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentException].callback = argumentCallback;
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentNullException].callback = argumentNullCallback;
  SWIG_csharp_exceptions_argument[SWIG_CSharpArgumentOutOfRangeException].callback = argumentOutOfRangeCallback;
}


/* Callback for returning strings to C# without leaking memory */
typedef char * (SWIGSTDCALL* SWIG_CSharpStringHelperCallback)(const char *);
static SWIG_CSharpStringHelperCallback SWIG_csharp_string_callback = NULL;


#ifdef __cplusplus
extern "C" 
#endif
SWIGEXPORT void SWIGSTDCALL SWIGRegisterStringCallback_libtelio(SWIG_CSharpStringHelperCallback callback) {
  SWIG_csharp_string_callback = callback;
}


/* Contract support */

#define SWIG_contract_assert(nullreturn, expr, msg) if (!(expr)) {SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentOutOfRangeException, msg, ""); return nullreturn; } else


#include "../../telio.h"


typedef void(*cs_telio_event_cb)(const char *);
void call_telio_event_cb(void *ctx, const char *msg) {
  cs_telio_event_cb cb = ctx;
  cb(msg);
}

typedef void(*cs_telio_logger_cb)(int, const char *);
void call_telio_logger_cb(void *ctx, int l, const char *msg) {
  cs_telio_logger_cb cb = ctx;
  cb(l, msg);
}

SWIGINTERN struct telio *new_telio(char const *features,telio_event_cb events,enum telio_log_level level,telio_logger_cb logger){
        telio *t;
        if (TELIO_RES_OK != telio_new(&t, features, events, level, logger)) {
            SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentException, "Failed to initiate telio", "features");
            return NULL;
        }
        return t;
    }
SWIGINTERN void delete_telio(struct telio *self){
        telio_destroy(self);
    }

#ifdef __cplusplus
extern "C" {
#endif

SWIGEXPORT void * SWIGSTDCALL CSharp_NordSecfTelio_new_Telio___(char * jarg1, cs_telio_event_cb jarg2, int jarg3, cs_telio_logger_cb jarg4) {
  void * jresult ;
  char *arg1 = (char *) 0 ;
  telio_event_cb arg2 ;
  enum telio_log_level arg3 ;
  telio_logger_cb arg4 ;
  struct telio *result = 0 ;
  
  arg1 = (char *)jarg1; 
  
  arg2 = (struct telio_event_cb) {
    .ctx = jarg2,
    .cb = call_telio_event_cb,
  };
  
  arg3 = (enum telio_log_level)jarg3; 
  
  arg4 = (struct telio_logger_cb) {
    .ctx = jarg4,
    .cb = call_telio_logger_cb,
  };
  
  result = (struct telio *)new_telio((char const *)arg1,arg2,arg3,arg4);
  jresult = (void *)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetDefaultAdapter___() {
  int jresult ;
  enum telio_adapter_type result;
  
  result = (enum telio_adapter_type)telio_get_default_adapter();
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT void SWIGSTDCALL CSharp_NordSecfTelio_delete_Telio___(void * jarg1) {
  struct telio *arg1 = (struct telio *) 0 ;
  
  arg1 = (struct telio *)jarg1; 
  delete_telio(arg1);
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_Start___(void * jarg1, char * jarg2, int jarg3) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_adapter_type arg3 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (enum telio_adapter_type)jarg3; 
  result = (enum telio_result)telio_start(arg1,(char const *)arg2,arg3);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_StartNamed___(void * jarg1, char * jarg2, int jarg3, char * jarg4) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_adapter_type arg3 ;
  char *arg4 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (enum telio_adapter_type)jarg3; 
  arg4 = (char *)jarg4; 
  result = (enum telio_result)telio_start_named(arg1,(char const *)arg2,arg3,(char const *)arg4);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_EnableMagicDns___(void * jarg1, char * jarg2) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (enum telio_result)telio_enable_magic_dns(arg1,(char const *)arg2);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_DisableMagicDns___(void * jarg1) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  result = (enum telio_result)telio_disable_magic_dns(arg1);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_Stop___(void * jarg1) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  result = (enum telio_result)telio_stop(arg1);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT unsigned long long SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetAdapterLuid___(void * jarg1) {
  unsigned long long jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  unsigned long long result;
  
  arg1 = (struct telio *)jarg1; 
  result = (unsigned long long)telio_get_adapter_luid(arg1);
  jresult = result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_SetPrivateKey___(void * jarg1, char * jarg2) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (enum telio_result)telio_set_private_key(arg1,(char const *)arg2);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetPrivateKey___(void * jarg1) {
  char * jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *result = 0 ;
  
  arg1 = (struct telio *)jarg1; 
  result = (char *)telio_get_private_key(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_NotifyNetworkChange___(void * jarg1, char * jarg2) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (enum telio_result)telio_notify_network_change(arg1,(char const *)arg2);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_ConnectToExitNode___(void * jarg1, char * jarg2, char * jarg3, char * jarg4) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  char *arg3 = (char *) 0 ;
  char *arg4 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (char *)jarg3; 
  arg4 = (char *)jarg4; 
  result = (enum telio_result)telio_connect_to_exit_node(arg1,(char const *)arg2,(char const *)arg3,(char const *)arg4);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_ConnectToExitNodeWithId___(void * jarg1, char * jarg2, char * jarg3, char * jarg4, char * jarg5) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  char *arg3 = (char *) 0 ;
  char *arg4 = (char *) 0 ;
  char *arg5 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (char *)jarg3; 
  arg4 = (char *)jarg4; 
  arg5 = (char *)jarg5; 
  result = (enum telio_result)telio_connect_to_exit_node_with_id(arg1,(char const *)arg2,(char const *)arg3,(char const *)arg4,(char const *)arg5);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_ConnectToExitNodePostquantum___(void * jarg1, char * jarg2, char * jarg3, char * jarg4, char * jarg5) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  char *arg3 = (char *) 0 ;
  char *arg4 = (char *) 0 ;
  char *arg5 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  arg3 = (char *)jarg3; 
  arg4 = (char *)jarg4; 
  arg5 = (char *)jarg5; 
  result = (enum telio_result)telio_connect_to_exit_node_postquantum(arg1,(char const *)arg2,(char const *)arg3,(char const *)arg4,(char const *)arg5);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_DisconnectFromExitNode___(void * jarg1, char * jarg2) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (enum telio_result)telio_disconnect_from_exit_node(arg1,(char const *)arg2);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_DisconnectFromExitNodes___(void * jarg1) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  result = (enum telio_result)telio_disconnect_from_exit_nodes(arg1);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_SetMeshnet___(void * jarg1, char * jarg2) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (enum telio_result)telio_set_meshnet(arg1,(char const *)arg2);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT int SWIGSTDCALL CSharp_NordSecfTelio_Telio_SetMeshnetOff___(void * jarg1) {
  int jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  enum telio_result result;
  
  arg1 = (struct telio *)jarg1; 
  result = (enum telio_result)telio_set_meshnet_off(arg1);
  jresult = (int)result; 
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GenerateSecretKey___(void * jarg1) {
  char * jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *result = 0 ;
  
  arg1 = (struct telio *)jarg1; 
  result = (char *)telio_generate_secret_key(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GeneratePublicKey___(void * jarg1, char * jarg2) {
  char * jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *arg2 = (char *) 0 ;
  char *result = 0 ;
  
  arg1 = (struct telio *)jarg1; 
  arg2 = (char *)jarg2; 
  result = (char *)telio_generate_public_key(arg1,(char const *)arg2);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetStatusMap___(void * jarg1) {
  char * jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *result = 0 ;
  
  arg1 = (struct telio *)jarg1; 
  result = (char *)telio_get_status_map(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetLastError___(void * jarg1) {
  char * jresult ;
  struct telio *arg1 = (struct telio *) 0 ;
  char *result = 0 ;
  
  arg1 = (struct telio *)jarg1; 
  result = (char *)telio_get_last_error(arg1);
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetVersionTag___() {
  char * jresult ;
  char *result = 0 ;
  
  result = (char *)telio_get_version_tag();
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


SWIGEXPORT char * SWIGSTDCALL CSharp_NordSecfTelio_Telio_GetCommitSha___() {
  char * jresult ;
  char *result = 0 ;
  
  result = (char *)telio_get_commit_sha();
  jresult = SWIG_csharp_string_callback((const char *)result); 
  free(result);
  return jresult;
}


#ifdef __cplusplus
}
#endif

