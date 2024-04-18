/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

/*
 * Based on https://git.zx2c4.com/wireguard-go/plain/conn/bind_std.go?id=12269c2761734b15625017d8565745096325392f
 */

package main

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type Keypair struct {
	sendNonce    atomic.Uint64
	send         cipher.AEAD
	receive      cipher.AEAD
	replayFilter replay.Filter
	isInitiator  bool
	created      time.Time
	localIndex   uint32
	remoteIndex  uint32
}

type Keypairs struct {
	sync.RWMutex
	current  *Keypair
	previous *Keypair
	next     atomic.Pointer[Keypair]
}

func (kp *Keypairs) Current() *Keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}

func (device *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		device.indexTable.Delete(key.localIndex)
	}
}
