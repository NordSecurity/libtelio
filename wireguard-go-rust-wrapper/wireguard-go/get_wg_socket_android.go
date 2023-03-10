package main

/*
#include <stdint.h>
*/
import "C"

import (
	"fmt"
	"golang.zx2c4.com/wireguard/conn"
)

const jsonFmt = "{ \"fd\": %d, \"err\": \"%v\"}"

func PlatformSpecific_GetWgSocket(handle C.int32_t, ipv6 bool) *C.char {
	entry, err := get_tunnel_entry(int32(handle))
	if err != nil {
		return C.CString(fmt.Sprintf(jsonFmt, -1, err))
	}
	if entry == nil {
		return C.CString(fmt.Sprintf(jsonFmt, -1, "PlatformSpecific_GetWgSocket: tunnel entry is nil"))
	}

	bind, ok := entry.bind.(*conn.StdNetBind)
	if !ok {
		return C.CString(fmt.Sprintf(jsonFmt, -1, "PlatformSpecific_GetWgSocket: casting to StdNetBind failed"))
	}

	var fd int
	var e error
	if ipv6 {
		fd, e = bind.PeekLookAtSocketFd6()
	} else {
		fd, e = bind.PeekLookAtSocketFd4()
	}

	if e != nil {
		return C.CString(fmt.Sprintf(jsonFmt, -1, e))
	}

	return C.CString(fmt.Sprintf(jsonFmt, fd, ""))
}

