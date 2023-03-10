// +build !windows

package main

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type interfaceWatcher struct { }

func (iw *interfaceWatcher) Configure(binder conn.BindSocketToInterface, tun *tun.NativeTun) { }

func watchInterface() (*interfaceWatcher, error) {
	var iw interfaceWatcher
	return &iw, nil
}

func (iw *interfaceWatcher) Destroy() { }

