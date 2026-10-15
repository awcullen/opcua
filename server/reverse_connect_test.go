// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"fmt"
	"net"
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
