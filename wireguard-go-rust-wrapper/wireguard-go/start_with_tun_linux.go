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

import (
	"unsafe"

	"github.com/NordSecurity/wireguard-go/tun"
)

func PlatformSpecific_StartWithTun(fd C.int32_t, log C.wg_go_log_cb) C.int32_t {
	if loggerFunc == 0 {
		loggerCtx = uintptr(unsafe.Pointer(log.ctx))
		loggerFunc = uintptr(unsafe.Pointer(log.fn))
	}

	watcher, err := watchInterface()
	if err != nil {
		errorf("Failed to initialize watch interface: %v", err)
		return -1
	}

	fd_tun, ifname, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil || fd_tun == nil {
		errorf("Failed to initialize tun interface from file descriptor %v", err)
		return -1
	}
	nativeTun := fd_tun.(*tun.NativeTun)

	return wg_go_start(ifname, nativeTun, watcher)
}
