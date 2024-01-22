//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import "net"

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	return
}
