/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

/*
 * Original file from: https://git.zx2c4.com/wireguard-go  tag: 0.0.20211016
 * https://git.zx2c4.com/wireguard-go/tree/conn/bind_std.go?h=0.0.20211016&id=f87e87af0d9a2d41e79770cf1422f01f7e8b303d
 */

package main

import (
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

// StdNetBind is meant to be a temporary solution on platforms for which
// the sticky socket / source caching behavior has not yet been implemented.
// It uses the Go's net package to implement networking.
// See LinuxSocketBind for a proper implementation on the Linux platform.
type StdNetBind struct {
	mu         sync.Mutex // protects following fields
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool
}

func NewStdNetBind() FullBind { return &StdNetBind{} }

type StdNetEndpoint net.UDPAddr

var _ conn.Bind = (*StdNetBind)(nil)
var _ conn.Endpoint = (*StdNetEndpoint)(nil)

func (*StdNetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := parseEndpoint(s)
	return (*StdNetEndpoint)(addr), err
}

func parseEndpoint(s string) (*net.UDPAddr, error) {
	// ensure that the host is an IP address

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if i := strings.LastIndexByte(host, '%'); i > 0 && strings.IndexByte(host, ':') >= 0 {
		// Remove the scope, if any. ResolveUDPAddr below will use it, but here we're just
		// trying to make sure with a small sanity test that this is a real IP address and
		// not something that's likely to incur DNS lookups.
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		addr.IP = ip4
	}
	return addr, err
}

func (*StdNetEndpoint) ClearSrc() {}

func (e *StdNetEndpoint) DstIP() net.IP {
	return (*net.UDPAddr)(e).IP
}

func (e *StdNetEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *StdNetEndpoint) DstToBytes() []byte {
	addr := (*net.UDPAddr)(e)
	out := addr.IP.To4()
	if out == nil {
		out = addr.IP
	}
	out = append(out, byte(addr.Port&0xff))
	out = append(out, byte((addr.Port>>8)&0xff))
	return out
}

func (e *StdNetEndpoint) DstToString() string {
	return (*net.UDPAddr)(e).String()
}

func (e *StdNetEndpoint) SrcToString() string {
	return ""
}

func listenNet(network string, addr net.IP, port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: addr, Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}

func (bind *StdNetBind) OpenOnAddr(ipv4addr net.IP, ipv6addr net.IP, uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var tries int

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var ipv4, ipv6 *net.UDPConn

	ipv4, port, err = listenNet("udp4", ipv4addr, port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	ipv6, port, err = listenNet("udp6", ipv6addr, port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		ipv4.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		ipv4.Close()
		return nil, 0, err
	}
	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		fns = append(fns, bind.makeReceiveIPv4(ipv4))
		bind.ipv4 = ipv4
	}
	if ipv6 != nil {
		fns = append(fns, bind.makeReceiveIPv6(ipv6))
		bind.ipv6 = ipv6
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, uint16(port), nil
}

func (bind *StdNetBind) OpenOnLocalhost(uport uint16) (recvFns []conn.ReceiveFunc, selectedPort uint16, err error) {
	return bind.OpenOnAddr(net.IPv4(127, 0, 0, 1), net.IPv6loopback, uport)
}

func (bind *StdNetBind) Open(uport uint16) (recvFns []conn.ReceiveFunc, selectedPort uint16, err error) {
	return bind.OpenOnAddr(net.IPv4zero, net.IPv6zero, uport)
}

func (bind *StdNetBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err1, err2 error
	if bind.ipv4 != nil {
		err1 = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		err2 = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (*StdNetBind) makeReceiveIPv4(connection *net.UDPConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, endpoint, err := connection.ReadFromUDP(buff)
		if endpoint != nil {
			endpoint.IP = endpoint.IP.To4()
		}
		return n, (*StdNetEndpoint)(endpoint), err
	}
}

func (*StdNetBind) makeReceiveIPv6(connection *net.UDPConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, endpoint, err := connection.ReadFromUDP(buff)
		return n, (*StdNetEndpoint)(endpoint), err
	}
}

func (bind *StdNetBind) Send(buff []byte, endpoint conn.Endpoint) error {
	var err error
	nend, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	bind.mu.Lock()
	blackhole := bind.blackhole4
	conn := bind.ipv4
	if nend.IP.To4() == nil {
		blackhole = bind.blackhole6
		conn = bind.ipv6
	}
	bind.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	_, err = conn.WriteToUDP(buff, (*net.UDPAddr)(nend))
	return err
}
