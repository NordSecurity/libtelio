// +build !android

package main

/*
#include <stdint.h>
*/
import "C"

func PlatformSpecific_GetWgSocket(handle C.int32_t, ipv6 bool) *C.char {
	return C.CString("{ \"fd\": -1, \"err\": \"\"}")
}

