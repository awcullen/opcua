// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"net"
	"testing"
)

type localAddrConn struct {
	net.Conn
	local net.Addr
}

func (c localAddrConn) LocalAddr() net.Addr { return c.local }

// TestAnUnusableRequestHostFallsBackToTheConnection: a request whose endpointUrl names no
// host, or the unspecified address, is answered with the address the connection reached.
func TestAnUnusableRequestHostFallsBackToTheConnection(t *testing.T) {
	conn := localAddrConn{local: &net.TCPAddr{IP: net.ParseIP("192.168.10.5"), Port: 48401}}
	conn6 := localAddrConn{local: &net.TCPAddr{IP: net.ParseIP("fd00::5"), Port: 48401}}
	for _, tc := range []struct {
		configured, requested string
		conn                  net.Conn
		want                  string
	}{
		{"opc.tcp://0.0.0.0:48401", "", conn, "opc.tcp://192.168.10.5:48401"},
		{"opc.tcp://0.0.0.0:48401", "opc.tcp://0.0.0.0:48401", conn, "opc.tcp://192.168.10.5:48401"},
		{"opc.tcp://[::]:48401", "opc.tcp://[::]:48401", conn6, "opc.tcp://[fd00::5]:48401"},
		{"opc.tcp://0.0.0.0:48401", "opc.tcp://plant-box:48401", conn, "opc.tcp://plant-box:48401"},
		{"opc.tcp://:48401", "", conn, "opc.tcp://192.168.10.5:48401"},
		// a configured host that is not unspecified is the operator's choice: kept.
		{"opc.tcp://box.example:48401", "opc.tcp://10.0.0.1:48401", conn, "opc.tcp://box.example:48401"},
		// nothing usable: unchanged.
		{"opc.tcp://0.0.0.0:48401", "", nil, "opc.tcp://0.0.0.0:48401"},
	} {
		if got := withHost(tc.configured, clientHost(tc.requested, tc.conn)); got != tc.want {
			t.Errorf("withHost(%q, clientHost(%q)) = %q, want %q", tc.configured, tc.requested, got, tc.want)
		}
	}
}
