//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

/*
 * Based on https://git.zx2c4.com/wireguard-go/plain/conn/bind_std.go?id=12269c2761734b15625017d8565745096325392f
 */

package main

// Fit within memory limits for iOS's Network Extension API, which has stricter requirements.
// These are vars instead of consts, because heavier network extensions might want to reduce
// them further.
var (
	QueueStagedSize                   = 128
	QueueOutboundSize                 = 1024
	QueueInboundSize                  = 1024
	QueueHandshakeSize                = 1024
	PreallocatedBuffersPerPool uint32 = 1024
)

const MaxSegmentSize = 1700
