// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

func TestReverseConnectStateKeepsSpareSocket(t *testing.T) {
	srv := &Server{reverseConnectKick: make(chan struct{}, 1)}
	target := &reverseConnectTarget{}
	now := time.Now()

	if !srv.beginReverseConnect(target, now) {
		t.Fatal("expected first socket to start")
	}
	if srv.beginReverseConnect(target, now) {
		t.Fatal("expected pending socket to block another socket")
	}

	srv.establishReverseConnect(target)
	select {
	case <-srv.reverseConnectKick:
	default:
		t.Fatal("expected established socket to request a replacement")
	}
	if !srv.beginReverseConnect(target, now) {
		t.Fatal("expected spare socket while a SecureChannel is active")
	}

	srv.endReverseConnect(target, false)
	select {
	case <-srv.reverseConnectKick:
		t.Fatal("failed pending socket must not trigger an immediate redial")
	default:
	}

	srv.endReverseConnect(target, true)
	select {
	case <-srv.reverseConnectKick:
	default:
		t.Fatal("expected closed SecureChannel to request a replacement")
	}
	if target.pending != 0 || target.established != 0 {
		t.Fatalf("expected empty state, got pending=%d established=%d", target.pending, target.established)
	}
}

func TestReverseConnectRejectBacksOff(t *testing.T) {
	srv := &Server{reverseConnectRejectTimeout: time.Minute, reverseConnectKick: make(chan struct{}, 1)}
	target := &reverseConnectTarget{}
	now := time.Now()

	srv.rejectReverseConnect(target, now)
	if srv.beginReverseConnect(target, now.Add(59*time.Second)) {
		t.Fatal("expected rejected client to back off")
	}
	if !srv.beginReverseConnect(target, now.Add(time.Minute)) {
		t.Fatal("expected socket after reject timeout")
	}
}

func TestWithReverseConnectClientURLsRejectsInvalidURL(t *testing.T) {
	for _, u := range []string{"://bad", "opc.tcp://"} {
		if err := WithReverseConnectClientURLs([]string{u}, 0)(&Server{}); err != ua.BadTCPEndpointURLInvalid {
			t.Errorf("%q: expected %v, got %v", u, ua.BadTCPEndpointURLInvalid, err)
		}
	}
	srv := &Server{}
	if err := WithReverseConnectClientURLs([]string{"opc.tcp://127.0.0.1:4843"}, 0)(srv); err != nil {
		t.Fatal(err)
	}
	if len(srv.reverseConnectTargets) != 1 || srv.reverseConnectTargets[0].host != "127.0.0.1:4843" {
		t.Fatalf("unexpected targets %+v", srv.reverseConnectTargets)
	}
}

func TestListenAndServeRejectsOversizedReverseHello(t *testing.T) {
	srv := newReverseTestServer(t, strings.Repeat("u", maxReverseHelloStringLength), "opc.tcp://127.0.0.1:1")
	if err := srv.ListenAndServe(); err != ua.BadTCPEndpointURLInvalid {
		t.Fatalf("expected %v, got %v", ua.BadTCPEndpointURLInvalid, err)
	}
}

// TestReverseConnectClientErrorBacksOff checks the ReverseHello encoding, that any client Error
// message triggers the reject backoff, and that the server does not answer an Error with an Error.
func TestReverseConnectClientErrorBacksOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	clientURL := "opc.tcp://" + ln.Addr().String()
	var logs syncBuffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	srv := newReverseTestServer(t, "urn:test:server", clientURL,
		WithReverseConnectRejectTimeout(time.Minute))
	srv.reverseConnectInterval = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		<-done
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	want := reverseHelloBytes("urn:test:server", srv.endpointURL)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("unexpected ReverseHello\n got % x\nwant % x", got, want)
	}

	var errMsg [16]byte
	binary.LittleEndian.PutUint32(errMsg[0:4], ua.MessageTypeError)
	binary.LittleEndian.PutUint32(errMsg[4:8], 16)
	binary.LittleEndian.PutUint32(errMsg[8:12], uint32(ua.BadTCPEndpointURLInvalid))
	binary.LittleEndian.PutUint32(errMsg[12:16], 0xFFFFFFFF)
	if _, err := conn.Write(errMsg[:]); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); err != io.EOF {
		t.Fatalf("expected server to close without reply, got n=%d err=%v", n, err)
	}

	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond))
	if extra, err := ln.Accept(); err == nil {
		extra.Close()
		t.Fatal("expected server to back off after client Error message")
	}
	if !strings.Contains(logs.String(), "rejected") || !strings.Contains(logs.String(), ln.Addr().String()) {
		t.Fatalf("expected client Error to be logged, got %q", logs.String())
	}
}

func TestReverseSocketWaitsForHelloWithoutDeadline(t *testing.T) {
	defer func(d time.Duration) { helloTimeout = d }(helloTimeout)
	helloTimeout = 200 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := newReverseTestServer(t, "urn:test:server", "opc.tcp://"+ln.Addr().String())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		<-done
	}()

	conn := acceptReverseHello(t, ln, srv)
	defer conn.Close()
	time.Sleep(3 * helloTimeout)
	if _, err := conn.Write(helloBytes(srv.endpointURL)); err != nil {
		t.Fatal(err)
	}
	var ack [8]byte
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		t.Fatalf("expected Acknowledge after delayed Hello: %v", err)
	}
	if binary.LittleEndian.Uint32(ack[0:4]) != ua.MessageTypeAck {
		t.Fatalf("expected Acknowledge, got % x", ack)
	}
}

func TestReverseConnectRedialsWhenWaitingSocketDropped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// default 5s interval: only a redial explains a prompt second socket.
	srv := newReverseTestServer(t, "urn:test:server", "opc.tcp://"+ln.Addr().String())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	defer func() {
		srv.Close()
		<-done
	}()

	quick := acceptReverseHello(t, ln, srv)
	quick.Close()
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))
	if extra, err := ln.Accept(); err == nil {
		extra.Close()
		t.Fatal("expected no immediate redial after a socket dropped at once")
	}

	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	held := acceptReverseHello(t, ln, srv)
	time.Sleep(reverseConnectMinRedialAge + 100*time.Millisecond)
	held.Close()
	start := time.Now()
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	next, err := ln.Accept()
	if err != nil {
		t.Fatalf("expected immediate redial after a held socket dropped: %v", err)
	}
	next.Close()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("expected immediate redial, took %v", d)
	}
}

func TestServerCloseDoesNotWaitForPendingReverseSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := newReverseTestServer(t, "urn:test:server", "opc.tcp://"+ln.Addr().String())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 16+len("urn:test:server")+len(srv.endpointURL))); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	srv.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe blocked on a socket waiting for Hello")
	}
	// Close itself sleeps 3s to let clients exit.
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("expected prompt shutdown, took %v", d)
	}
}

func BenchmarkBeginReverseConnect(b *testing.B) {
	srv := &Server{reverseConnectKick: make(chan struct{}, 1)}
	target := &reverseConnectTarget{}
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !srv.beginReverseConnect(target, now) {
			b.Fatal("expected reverse connect to start")
		}
		srv.endReverseConnect(target, false)
	}
}

func BenchmarkBeginReverseConnectRejected(b *testing.B) {
	now := time.Now()
	srv := &Server{reverseConnectKick: make(chan struct{}, 1)}
	target := &reverseConnectTarget{rejectedUntil: now.Add(time.Minute)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if srv.beginReverseConnect(target, now) {
			b.Fatal("expected reverse connect to back off")
		}
	}
}

func newReverseTestServer(t *testing.T, applicationURI, clientURL string, opts ...Option) *Server {
	t.Helper()
	srv, err := New(
		ua.ApplicationDescription{ApplicationURI: applicationURI, ApplicationType: ua.ApplicationTypeServer},
		"./pki/server.crt",
		"./pki/server.key",
		freeServerEndpointURL(t),
		append([]Option{WithReverseConnectClientURLs([]string{clientURL}, 0)}, opts...)...,
	)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func freeServerEndpointURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return "opc.tcp://" + ln.Addr().String()
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func acceptReverseHello(t *testing.T, ln net.Listener, srv *Server) net.Conn {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	want := reverseHelloBytes(srv.localDescription.ApplicationURI, srv.endpointURL)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

func helloBytes(endpointURL string) []byte {
	n := 32 + len(endpointURL)
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b[0:4], ua.MessageTypeHello)
	binary.LittleEndian.PutUint32(b[4:8], uint32(n))
	binary.LittleEndian.PutUint32(b[8:12], 0)
	binary.LittleEndian.PutUint32(b[12:16], 65535)
	binary.LittleEndian.PutUint32(b[16:20], 65535)
	binary.LittleEndian.PutUint32(b[20:24], 0)
	binary.LittleEndian.PutUint32(b[24:28], 0)
	binary.LittleEndian.PutUint32(b[28:32], uint32(len(endpointURL)))
	copy(b[32:], endpointURL)
	return b
}

func reverseHelloBytes(serverURI, endpointURL string) []byte {
	n := 16 + len(serverURI) + len(endpointURL)
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b[0:4], ua.MessageTypeReverseHello)
	binary.LittleEndian.PutUint32(b[4:8], uint32(n))
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(serverURI)))
	off := 12 + copy(b[12:], serverURI)
	binary.LittleEndian.PutUint32(b[off:off+4], uint32(len(endpointURL)))
	copy(b[off+4:], endpointURL)
	return b
}
