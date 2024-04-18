/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

/*
 * Based on https://git.zx2c4.com/wireguard-go/plain/conn/bind_std.go?id=12269c2761734b15625017d8565745096325392f
 */

package main

import "golang.zx2c4.com/wireguard/conn"

/* Reduce memory consumption for Android */

const (
	QueueStagedSize            = conn.IdealBatchSize
	QueueOutboundSize          = 1024
	QueueInboundSize           = 1024
	QueueHandshakeSize         = 1024
	MaxSegmentSize             = (1 << 16) - 1 // largest possible UDP datagram
	PreallocatedBuffersPerPool = 4096
)
