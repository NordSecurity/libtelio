//go:build !linux && !openbsd && !freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

/*
 * Original file from: https://git.zx2c4.com/wireguard-go  tag: 0.0.20211016
 * https://git.zx2c4.com/wireguard-go/tree/conn/mark_default.go?h=0.0.20211016&id=f87e87af0d9a2d41e79770cf1422f01f7e8b303d
 */

package main

func (bind *StdNetBind) SetMark(mark uint32) error {
	return nil
}
