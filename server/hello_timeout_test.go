// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

func TestWithHelloTimeoutRejectsNonPositive(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		if err := WithHelloTimeout(d)(&Server{}); err != ua.BadInvalidArgument {
			t.Errorf("%v: expected %v, got %v", d, ua.BadInvalidArgument, err)
		}
	}
}

func TestHelloTimeoutClosesIdleConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv, err := New(
		ua.ApplicationDescription{ApplicationURI: "urn:test:server", ApplicationType: ua.ApplicationTypeServer},
		"./pki/server.crt",
		"./pki/server.key",
		"opc.tcp://"+addr,
		WithHelloTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		<-done
	}()

	var conn net.Conn
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("expected server to close idle connection: %v", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 2*time.Second {
		t.Fatalf("expected close after ~200ms, took %v", d)
	}
}
