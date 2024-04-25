package main

import (
	"log"
	"sync"

	"github.com/NordSecurity/wireguard-go/conn"
	"github.com/NordSecurity/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type interfaceWatcherEvent struct {
	iface *winipcfg.MibIPInterfaceRow
}

type interfaceWatcher struct {
	binder conn.BindSocketToInterface
	tun    *tun.NativeTun

	default4                uint32
	default6                uint32
	setupMutex              sync.Mutex
	interfaceChangeCallback winipcfg.ChangeCallback
	changeCallbacks4        []winipcfg.ChangeCallback
	changeCallbacks6        []winipcfg.ChangeCallback
	storedEvents            []interfaceWatcherEvent
}

func (iw *interfaceWatcher) setup(family winipcfg.AddressFamily, mtu uint32) {
	var changeCallbacks *[]winipcfg.ChangeCallback
	var ipversion string
	var index uint32
	if family == windows.AF_INET {
		changeCallbacks = &iw.changeCallbacks4
		ipversion = "v4"
	} else if family == windows.AF_INET6 {
		changeCallbacks = &iw.changeCallbacks6
		ipversion = "v6"
	} else {
		return
	}
	if len(*changeCallbacks) != 0 {
		for _, cb := range *changeCallbacks {
			cb.Unregister()
		}
		*changeCallbacks = nil
	}
	var err error

	log.Printf("Monitoring default %s routes", ipversion)
	*changeCallbacks, index, err = monitorDefaultRoutes(family, iw.binder, mtu == 0, false, iw.tun, iw)
	if err != nil {
		errorf("Failed to bind sockets to default routes: %v", err)
		return
	}

	if family == windows.AF_INET {
		iw.default4 = index
	} else if family == windows.AF_INET6 {
		iw.default6 = index
	}
}

func (iw *interfaceWatcher) Configure(binder conn.BindSocketToInterface, tun *tun.NativeTun) {
	iw.setupMutex.Lock()
	defer iw.setupMutex.Unlock()

	iw.binder, iw.tun = binder, tun
	for _, event := range iw.storedEvents {
		if event.iface.InterfaceLUID == winipcfg.LUID(iw.tun.LUID()) {
			iw.setup(event.iface.Family, event.iface.NLMTU)
		}
	}
	iw.storedEvents = nil
}

func watchInterface() (*interfaceWatcher, error) {
	var iw interfaceWatcher
	var err error
	iw.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		iw.setupMutex.Lock()
		defer iw.setupMutex.Unlock()

		if notificationType != winipcfg.MibAddInstance {
			return
		}
		if iw.tun == nil {
			iw.storedEvents = append(iw.storedEvents, interfaceWatcherEvent{iface})
			return
		}
		if iface.InterfaceLUID != winipcfg.LUID(iw.tun.LUID()) {
			return
		}
		iw.setup(iface.Family, iface.NLMTU)
	})
	if err != nil {
		errorf("Failed to register interface change callback: %v", err)
		return nil, err
	}
	return &iw, nil
}

func (iw *interfaceWatcher) Destroy() {
	iw.setupMutex.Lock()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	tun := iw.tun
	iw.setupMutex.Unlock()

	if interfaceChangeCallback != nil {
		interfaceChangeCallback.Unregister()
	}
	for _, cb := range changeCallbacks4 {
		cb.Unregister()
	}
	for _, cb := range changeCallbacks6 {
		cb.Unregister()
	}

	iw.setupMutex.Lock()
	if interfaceChangeCallback == iw.interfaceChangeCallback {
		iw.interfaceChangeCallback = nil
	}
	for len(changeCallbacks4) > 0 && len(iw.changeCallbacks4) > 0 {
		iw.changeCallbacks4 = iw.changeCallbacks4[1:]
		changeCallbacks4 = changeCallbacks4[1:]
	}
	for len(changeCallbacks6) > 0 && len(iw.changeCallbacks6) > 0 {
		iw.changeCallbacks6 = iw.changeCallbacks6[1:]
		changeCallbacks6 = changeCallbacks6[1:]
	}

	if tun != nil && iw.tun == tun {
		// It seems that the Windows networking stack doesn't like it when we destroy interfaces that have active
		// routes, so to be certain, just remove everything before destroying.
		luid := winipcfg.LUID(tun.LUID())
		luid.FlushRoutes(windows.AF_INET)
		luid.FlushIPAddresses(windows.AF_INET)
		luid.FlushDNS(windows.AF_INET)
		luid.FlushRoutes(windows.AF_INET6)
		luid.FlushIPAddresses(windows.AF_INET6)
		luid.FlushDNS(windows.AF_INET6)
	}
	iw.setupMutex.Unlock()
}
