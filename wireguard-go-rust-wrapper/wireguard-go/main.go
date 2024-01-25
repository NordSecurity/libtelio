package main

/*
#include <stdint.h>
#include <stdlib.h>

#ifndef _WG_GO_LOG_CB
  #define _WG_GO_LOG_CB
	typedef struct _wg_go_log_cb {
			void *ctx;
			void (*fn)(void*, int, const char*);
	} wg_go_log_cb;
#endif

static void callLogger(void *func, void *ctx, int level, const char *msg) {
    ((void(*)(void*, int, const char *))func)(ctx, level, msg);
}

*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type CLogger struct {
	level C.int
}

type TunnelEntry struct {
	name    string
	device  *device.Device
	handle  int32
	tun     *tun.NativeTun
	bind    conn.Bind
	watcher *interfaceWatcher
}

var tunnels sync.Map
var OutOfFDError = errors.New("Out of file descriptors")
var GetDeviceError = errors.New("Failed to get the device")
var InvalidHandle = errors.New("Invalid handle")
var loggerFunc uintptr = 0
var loggerCtx uintptr = 0

var critical_logger *CLogger = &CLogger{level: 1}
var error_logger *CLogger = &CLogger{level: 2}
var warning_logger *CLogger = &CLogger{level: 3}
var info_logger *CLogger = &CLogger{level: 4}
var debug_logger *CLogger = &CLogger{level: 5}
var trace_logger *CLogger = &CLogger{level: 6}

func (l CLogger) Printf(format string, args ...interface{}) {
	if loggerFunc == 0 {
		return
	}
	message := C.CString(fmt.Sprintf(format, args...))
	C.callLogger(unsafe.Pointer(loggerFunc), unsafe.Pointer(loggerCtx), l.level, message)
	C.free(unsafe.Pointer(message))
}

func criticalf(format string, args ...interface{}) {
	critical_logger.Printf(format, args...)
}

func errorf(format string, args ...interface{}) {
	error_logger.Printf(format, args...)
}

func warningf(format string, args ...interface{}) {
	warning_logger.Printf(format, args...)
}

func infof(format string, args ...interface{}) {
	info_logger.Printf(format, args...)
}

func debugf(format string, args ...interface{}) {
	debug_logger.Printf(format, args...)
}

func tracef(format string, args ...interface{}) {
	trace_logger.Printf(format, args...)
}

func CreateDeviceLogger() *device.Logger {
	return &device.Logger{debugf, errorf}
}

func get_free_tunnel_handle() (int32, error) {
	var handle int32
	rand.Seed(time.Now().UnixNano())
	start := rand.Int31()

	for handle = start; handle < math.MaxInt32; handle++ {
		if _, exists := tunnels.Load(handle); !exists {
			return handle, nil
		}
	}

	for handle = 0; handle < start; handle++ {
		if _, exists := tunnels.Load(handle); !exists {
			return handle, nil
		}
	}

	return 0, OutOfFDError
}

func get_tunnel_entry(handle int32) (*TunnelEntry, error) {
	if handle != -1 {
		val, ok1 := tunnels.Load(handle)
		nlte, ok2 := val.(*TunnelEntry)
		if !ok1 || !ok2 {
			return nil, GetDeviceError
		}
		return nlte, nil
	}
	return nil, InvalidHandle
}

//export wg_go_start_named
func wg_go_start_named(name *C.char, log C.wg_go_log_cb) C.int32_t {
	var watcher *interfaceWatcher
	var err error
	if loggerFunc == 0 {
		loggerCtx = uintptr(unsafe.Pointer(log.ctx))
		loggerFunc = uintptr(unsafe.Pointer(log.fn))
	}

	ifname := C.GoString(name)

	if runtime.GOOS == "windows" {
		watcher, err = watchInterface()
		if err != nil {
			errorf("Failed to initialize watch interface: %v", err)
			return -1
		}
	}

	nativeTun, err := PlatformSpecific_CreateTun(ifname)
	if err != nil || nativeTun == nil {
		errorf("Failed to create tun interface: %v", err)
		return -1
	}

	return wg_go_start(ifname, nativeTun, watcher)
}

func wg_go_start(ifname string, nativeTun *tun.NativeTun, watcher *interfaceWatcher) C.int32_t {
	handle, err := get_free_tunnel_handle()
	if err != nil {
		errorf("Failed to find free tunnel handle: %v", err)
		return -1
	}

	var bind conn.Bind
	if runtime.GOOS == "android" {
		// On Android we need to retrieve WireGuard file descriptors in order to protect them.
		//  (https://developer.android.com/reference/kotlin/android/net/VpnService#protect)
		// This is implemented in StdNetBind::PeekLookAtSocketFd4() / PeekLookAtSocketFd6().
		//  (https://github.com/WireGuard/wireguard-go/blob/master/conn/boundif_android.go)
		// Unfortunately NewDefaultBind() creates LinuxSocketBind on Android.
		// NewStdNetBind() returns StdNetBind.
		// (Not sure what side effects can happen because of this.)
		bind = conn.NewStdNetBind()
	} else if runtime.GOOS == "windows" {
		bind = PlatformSpecific_GetBind(watcher)
	} else {
		bind = conn.NewDefaultBind()
	}

	dev_logger := CreateDeviceLogger()

	dev := device.NewDevice(nativeTun, bind, dev_logger)

	infof("Setting device up")
	dev.Up()

	if watcher != nil {
		if runtime.GOOS == "windows" {
			watcher.Configure(bind.(conn.BindSocketToInterface), nativeTun)
		}
	}

	entry := TunnelEntry{
		name:    ifname,
		handle:  handle,
		device:  dev,
		tun:     nativeTun,
		bind:    bind,
		watcher: watcher,
	}

	tunnels.Store(handle, &entry)

	return C.int32_t(handle)
}

func get_errno_from_error(err error) int64 {
	errno := int64(0)
	if err != nil {
		var status *device.IPCError
		if !errors.As(err, &status) {
			errno = ipc.IpcErrorUnknown
		} else {
			if status != nil {
				errno = status.ErrorCode()
			}
		}
	}
	return errno
}

//export wg_go_send_uapi_cmd
func wg_go_send_uapi_cmd(handle C.int32_t, cmd *C.char) *C.char {
	entry, err := get_tunnel_entry(int32(handle))
	if err != nil || entry == nil {
		errorf("entry is nil or error: %v", err)
		return nil
	}

	lines := strings.Split(C.GoString(cmd), "\n")
	command := strings.Join(lines[1:], "\n")
	op := lines[0]

	switch op {
	case "set=1":
		reader := strings.NewReader(command)
		err = entry.device.IpcSetOperation(reader)
		return C.CString(fmt.Sprintf("errno=%d\n\n", get_errno_from_error(err)))
	case "get=1":
		buf := new(strings.Builder)
		err = entry.device.IpcGetOperation(buf)
		ret := buf.String()
		ret += fmt.Sprintf("errno=%d\n\n", get_errno_from_error(err))
		return C.CString(ret)
	default:
		errorf("invalid UAPI operation: %v", op)
		return nil
	}
}

//export wg_go_start_with_tun
func wg_go_start_with_tun(fd C.int32_t, log C.wg_go_log_cb) C.int32_t {
	return PlatformSpecific_StartWithTun(fd, log)
}

//export wg_go_get_wg_socket
func wg_go_get_wg_socket(handle C.int32_t, ipv6 bool, cmd *C.char) *C.char {
	return PlatformSpecific_GetWgSocket(handle, ipv6)
}

//export wg_go_free_cmd_res
func wg_go_free_cmd_res(resp *C.char) {
	if resp != nil {
		C.free(unsafe.Pointer(resp))
	}
}

//export wg_go_stop
func wg_go_stop(handle C.int32_t) {
	entry, err := get_tunnel_entry(int32(handle))
	if err != nil || entry == nil {
		errorf("entry is nil or error: %v", err)
		return
	}

	if entry.watcher != nil {
		entry.watcher.Destroy()
	}
	entry.device.Close()
	entry.tun.Close()
	tunnels.Delete(handle)
	infof("Shutting down")
}

//export wg_go_get_adapter_luid
func wg_go_get_adapter_luid(handle C.int32_t) C.uint64_t {
	entry, err := get_tunnel_entry(int32(handle))
	if err != nil || entry == nil {
		errorf("entry is nil or error: %v", err)
		return 0
	}

	luid := PlatformSpecific_GetLUID(entry)
	return C.uint64_t(luid)
}

// This function is added in order to have a way of validating during link time
// that the proper version of wireguard-go library is linked.
// In the past we had an accident where some old version of wireguard-go was linked
// into libtelio in the release build. The root-cause is not found yet.
// When changes to the wireguard-go are done the version number should be updated.
// There is wireguard-go-version-update-check job in GitHub Actions validating
// that this version was updated when there was a change in the wireguard-go code.
//
//export wg_go_version_4_2_2
func wg_go_version_4_2_2() {}

func main() {}
