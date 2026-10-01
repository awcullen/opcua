// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

func TestCloseShutdownCountdown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		options  []server.Option
		min, max time.Duration
	}{
		{name: "default", min: 3 * time.Second, max: 5 * time.Second},
		{name: "custom", options: []server.Option{server.WithShutdownCountdown(1500 * time.Millisecond)}, min: 1500 * time.Millisecond, max: 3 * time.Second},
		{name: "zero", options: []server.Option{server.WithShutdownCountdown(0)}, max: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			ln.Close()
			endpoint := fmt.Sprintf("opc.tcp://127.0.0.1:%d", port)
			srv, err := server.New(ua.ApplicationDescription{ApplicationURI: "urn:shutdown-test", ApplicationType: ua.ApplicationTypeServer},
				"./pki/server.crt", "./pki/server.key", endpoint, tc.options...)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.ListenAndServe() }()
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("server did not start listening")
				}
			}

			start := time.Now()
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != ua.BadServerHalted {
				t.Fatalf("ListenAndServe() = %v, want BadServerHalted", err)
			}
			if elapsed := time.Since(start); elapsed < tc.min || elapsed > tc.max {
				t.Fatalf("Close took %v, want between %v and %v", elapsed, tc.min, tc.max)
			}
			ln, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				t.Fatalf("port not released after Close: %v", err)
			}
			ln.Close()
		})
	}
}

func TestWithShutdownCountdownRejectsNegative(t *testing.T) {
	_, err := server.New(ua.ApplicationDescription{ApplicationURI: "urn:shutdown-test", ApplicationType: ua.ApplicationTypeServer},
		"./pki/server.crt", "./pki/server.key", "opc.tcp://127.0.0.1:4840", server.WithShutdownCountdown(-time.Second))
	if err == nil {
		t.Fatal("expected an error for a negative countdown")
	}
}
