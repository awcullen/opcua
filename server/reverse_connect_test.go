// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// TestReverseConnect starts a server that connects to a client listener, checks the
// ReverseHello, then opens sessions over reverse connections, including after the
// client was unreachable and after a connection was dropped.
func TestReverseConnect(t *testing.T) {
	defer server.SetReverseConnectDelays(50*time.Millisecond, 200*time.Millisecond)()

	// reserve a port, then release it so the server's first dials fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := ln.Addr().String()
	ln.Close()

	const rcPort = 46011
	rcEndpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, rcPort)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:  fmt.Sprintf("urn:%s:reverseconnect", host),
			ApplicationName: ua.LocalizedText{Text: "reverseconnect"},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{rcEndpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		rcEndpointURL,
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithAuthenticateAnonymousIdentityFunc(func(ua.AnonymousIdentity, string, string) error { return nil }),
		server.WithReverseConnect("opc.tcp://"+clientAddr),
	)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		if err := <-served; err != ua.BadServerHalted {
			t.Errorf("ListenAndServe returned %v", err)
		}
	}()

	// let the server fail a few dials, then start listening: it must reconnect.
	time.Sleep(300 * time.Millisecond)
	ln, err = net.Listen("tcp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// the first message on a reverse connection is a ReverseHello naming the server.
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	serverURI, gotEndpointURL, err := client.ReadReverseHello(conn)
	if err != nil {
		t.Fatalf("reading ReverseHello: %v", err)
	}
	if serverURI != fmt.Sprintf("urn:%s:reverseconnect", host) || gotEndpointURL != rcEndpointURL {
		t.Fatalf("ReverseHello = (%q, %q)", serverURI, gotEndpointURL)
	}
	// drop the connection without using it: the server must open another one.
	conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		policies := [][]client.Option{
			{},
			{
				client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
				client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			},
		}[i]
		opts := append([]client.Option{
			client.WithInsecureSkipVerify(),
			client.WithDialer(client.ReverseConnectDialer(ln, rcEndpointURL)),
		}, policies...)
		ch, err := client.Dial(ctx, rcEndpointURL, opts...)
		if err != nil {
			t.Fatalf("session %d: dial over reverse connection: %v", i, err)
		}
		res, err := ch.Read(ctx, &ua.ReadRequest{
			NodesToRead: []ua.ReadValueID{{NodeID: ua.VariableIDServerServerStatusState, AttributeID: ua.AttributeIDValue}},
		})
		if err != nil {
			ch.Abort(ctx)
			t.Fatalf("session %d: read: %v", i, err)
		}
		if res.Results[0].StatusCode.IsBad() {
			t.Fatalf("session %d: read status %v", i, res.Results[0].StatusCode)
		}
		t.Logf("session %d over reverse connect: policy %s, ServerState = %v", i, ch.SecurityPolicyURI(), res.Results[0].Value)
		if err := ch.Close(ctx); err != nil {
			t.Fatalf("session %d: close: %v", i, err)
		}
	}
}

// TestWithReverseConnectRejectsInvalidURL checks the client URL is validated.
func TestWithReverseConnectRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"http://localhost:4840", "opc.tcp://localhost", "opc.tcp://:4840", "::"} {
		_, err := server.New(
			ua.ApplicationDescription{ApplicationURI: "urn:x", ApplicationType: ua.ApplicationTypeServer},
			"./pki/server.crt", "./pki/server.key", "opc.tcp://localhost:46012",
			server.WithReverseConnect(u),
		)
		if err != ua.BadTCPEndpointURLInvalid {
			t.Errorf("WithReverseConnect(%q): err = %v, want BadTCPEndpointURLInvalid", u, err)
		}
	}
}

// startReverseConnectServer starts a server that reverse connects to clientAddr and
// returns a func that closes it.
func startReverseConnectServer(t *testing.T, port int, clientAddr string, opts ...server.Option) func() {
	t.Helper()
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:  fmt.Sprintf("urn:%s:reverseconnect", host),
			ApplicationName: ua.LocalizedText{Text: "reverseconnect"},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		append([]server.Option{
			server.WithSecurityPolicyNone(true),
			server.WithInsecureSkipVerify(),
			server.WithReverseConnect("opc.tcp://" + clientAddr),
		}, opts...)...,
	)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	return func() {
		srv.Close()
		<-served
	}
}

// TestReverseConnectToAPeerThatIsNotAClientBacksOff points the server at a peer that
// speaks first and is not an OPC UA client (an SSH banner, as a mistyped port would
// find). Each socket fails to open a secure channel, so the server must back off
// rather than redial at once.
func TestReverseConnectToAPeerThatIsNotAClientBacksOff(t *testing.T) {
	defer server.SetReverseConnectDelays(50*time.Millisecond, 200*time.Millisecond)()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	var mu sync.Mutex
	var states []error
	stop := startReverseConnectServer(t, 46013, ln.Addr().String(),
		server.WithReverseConnectStateFunc(func(clientURL string, err error) {
			mu.Lock()
			states = append(states, err)
			mu.Unlock()
		}))
	defer stop()
	time.Sleep(1 * time.Second)
	mu.Lock()
	sawFailure := false
	for _, err := range states {
		if err != nil && strings.Contains(err.Error(), "did not open a secure channel") {
			sawFailure = true
		}
	}
	mu.Unlock()
	if !sawFailure {
		t.Errorf("the state func never reported the failed secure channel; got %v", states)
	}
	// 50+100+200+200+200 ms of backoff fit in a second: about six dials.
	if n := accepted.Load(); n > 10 {
		t.Fatalf("the server dialled a peer that is not a client %d times in 1s; want backoff (at most 10)", n)
	}
}

// TestReverseConnectHoldsOneSocketPerClient points the server at a peer that sends a
// byte and then holds every socket open. The server must not open a second socket
// while the first is open.
func TestReverseConnectHoldsOneSocketPerClient(t *testing.T) {
	defer server.SetReverseConnectDelays(10*time.Millisecond, 20*time.Millisecond)()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var open, maxOpen atomic.Int64
	var conns sync.WaitGroup
	defer conns.Wait()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := open.Add(1)
			for m := maxOpen.Load(); n > m && !maxOpen.CompareAndSwap(m, n); m = maxOpen.Load() {
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer open.Add(-1)
				defer conn.Close()
				conn.Write([]byte{0})
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	stop := startReverseConnectServer(t, 46014, ln.Addr().String())
	defer stop()
	time.Sleep(500 * time.Millisecond)
	if n := maxOpen.Load(); n != 1 {
		t.Fatalf("the server held %d sockets open to one client at once; want 1", n)
	}
}
