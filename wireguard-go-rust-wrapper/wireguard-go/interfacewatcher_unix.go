//go:build !windows

package main

import (
	"github.com/NordSecurity/wireguard-go/conn"
	"github.com/NordSecurity/wireguard-go/tun"
)

type interfaceWatcher struct{}

func (iw *interfaceWatcher) Configure(binder conn.BindSocketToInterface, tun *tun.NativeTun) {}

func watchInterface() (*interfaceWatcher, error) {
	var iw interfaceWatcher
	return &iw, nil
}

func (iw *interfaceWatcher) Destroy() {}
