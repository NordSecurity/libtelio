//go:build !windows
// +build !windows

package main

import "C"

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type Binder struct{}

func PlatformSpecific_CreateTun(ifname string) (*tun.NativeTun, error) {
	infof("Creating wintun interface")
	wintun, err := tun.CreateTUN(ifname, 1420) //FIXME: MTU 1420, 1280, ...?
	if err != nil || wintun == nil {
		return nil, err
	}
	nativeTun := wintun.(*tun.NativeTun)
	return nativeTun, err
}

func PlatformSpecific_GetLUID(entry *TunnelEntry) C.size_t {
	return C.size_t(entry.handle)
}

func PlatformSpecific_GetProxyListenPort(_ *TunnelEntry) uint16 {
	return 0
}

func PlatformSpecific_Bind(b Binder) {}

func PlatformSpecific_GetBind(_ *interfaceWatcher) conn.Bind {
	return conn.NewDefaultBind()
}
