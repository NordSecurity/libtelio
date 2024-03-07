package main

import "C"

import (
	"runtime"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"

	"crypto/sha256"

	"github.com/google/uuid"
)

func PlatformSpecific_CreateTun(ifname string) (*tun.NativeTun, error) {
	tun.WintunTunnelType = ifname

	// Generate deterministic GUID from the adapter name.
	// Since NordVPN and NordLayer use different adapter names, the resuting GUIDs will
	// always be different, but they will stay consistent for the same adapter name.
	networkProfileUuid := uuid.NewHash(sha256.New(), uuid.Nil, []byte(ifname), 1)
	networkProfileGuidString := "{" + networkProfileUuid.String() + "}"
	networkProfileGuid, _ := windows.GUIDFromString(networkProfileGuidString)

	infof("Creating wintun interface %s with GUID %s", ifname, networkProfileGuidString)
	wintun, err := tun.CreateTUNWithRequestedGUID(ifname, &networkProfileGuid, 0)
	if err != nil || wintun == nil {
		return nil, err
	}
	nativeTun := wintun.(*tun.NativeTun)

	wintunVersion, err := nativeTun.RunningVersion()
	if err != nil {
		errorf("Unable to determine Wintun version: %v", err)
	} else {
		infof("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
	}

	return nativeTun, err
}

func PlatformSpecific_GetLUID(entry *TunnelEntry) C.size_t {
	return C.size_t(entry.tun.LUID())
}

func PlatformSpecific_GetProxyListenPort(entry *TunnelEntry) uint16 {
	bind, ok := entry.bind.(*Binder)
	if ok {
		return bind.local_port
	} else {
		errorf("Was not able to get windows Binder for entry %v", entry)
		return 0
	}

}

func PlatformSpecific_Bind(b Binder) {
	if runtime.GOOS == "windows" {
		if b.watcher.default4 != 0 {
			b.FullBind.BindSocketToInterface4(b.watcher.default4, false)
		}
		if b.watcher.default6 != 0 {
			b.FullBind.BindSocketToInterface6(b.watcher.default6, false)
		}
	}
}

type FullBind interface {
	conn.Bind
	conn.BindSocketToInterface
	OpenOnLocalhost(port uint16) ([]conn.ReceiveFunc, uint16, error)
}

type Binder struct {
	FullBind
	local_bind FullBind
	watcher    *interfaceWatcher
	local_port uint16
}

func (b Binder) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	recv_fns, actual_port, err := b.FullBind.Open(port)
	if err != nil {
		return recv_fns, actual_port, err
	}

	recv_fns_local, local_port, err := b.local_bind.OpenOnLocalhost(port)
	recv_fns = append(recv_fns, recv_fns_local...)

	if err != nil {
		return recv_fns, actual_port, err
	}

	b.local_port = local_port

	PlatformSpecific_Bind(b)

	return recv_fns, actual_port, err
}

func (b Binder) Send(buf [][]byte, ep conn.Endpoint) error {
	if ep.DstIP().IsLoopback() {
		return b.local_bind.Send(buf, ep)
	}

	return b.FullBind.Send(buf, ep)
}

func (b Binder) Close() error {
	b.FullBind.Close()
	return b.local_bind.Close()
}

func PlatformSpecific_GetBind(watcher *interfaceWatcher) conn.Bind {
	return &Binder{
		NewDefaultBind().(FullBind),
		NewDefaultBind(),
		watcher,
		0,
	}
}
