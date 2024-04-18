//go:build !linux

/*
 * Based on https://git.zx2c4.com/wireguard-go/plain/conn/bind_std.go?id=12269c2761734b15625017d8565745096325392f
 */

package main

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
