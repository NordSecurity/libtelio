// +build !linux

package main

/*
#include <stdint.h>

#ifndef _WG_GO_LOG_CB
  #define _WG_GO_LOG_CB
  typedef struct _wg_go_log_cb {
      void *ctx;
      void (*fn)(void*, int, const char*);
  } wg_go_log_cb;
#endif

*/
import "C"

func PlatformSpecific_StartWithTun(fd C.int32_t, log C.wg_go_log_cb) C.int32_t {
  return -1
}
