// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

func TestReadReverseHello(t *testing.T) {
	maxURI := strings.Repeat("u", maxReverseHelloStringLength-1)
	tooLong := strings.Repeat("u", maxReverseHelloStringLength)
	wrongType := testReverseHelloBytes("urn:server", "opc.tcp://127.0.0.1:4840")
	binary.LittleEndian.PutUint32(wrongType[0:4], ua.MessageTypeHello)
	tooLarge := testReverseHelloBytes("urn:server", "opc.tcp://127.0.0.1:4840")
	binary.LittleEndian.PutUint32(tooLarge[4:8], maxReverseHelloSize+1)
	tooSmall := testReverseHelloBytes("", "")
	binary.LittleEndian.PutUint32(tooSmall[4:8], 15)
	nullStrings := testReverseHelloBytes("", "")
	binary.LittleEndian.PutUint32(nullStrings[8:12], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(nullStrings[12:16], 0xFFFFFFFF)

	tests := []struct {
		name        string
		msg         []byte
		serverURI   string
		endpointURL string
		err         error
	}{
		{"valid", testReverseHelloBytes("urn:server", "opc.tcp://127.0.0.1:4840"), "urn:server", "opc.tcp://127.0.0.1:4840", nil},
		{"max length strings", testReverseHelloBytes(maxURI, maxURI), maxURI, maxURI, nil},
		{"null strings", nullStrings, "", "", nil},
		{"server uri too long", testReverseHelloBytes(tooLong, "opc.tcp://127.0.0.1:4840"), "", "", ua.BadTCPEndpointURLInvalid},
		{"endpoint url too long", testReverseHelloBytes("urn:server", tooLong), "", "", ua.BadTCPEndpointURLInvalid},
		{"message too large", tooLarge, "", "", ua.BadTCPEndpointURLInvalid},
		{"message too small", tooSmall, "", "", ua.BadDecodingError},
		{"wrong message type", wrongType, "", "", ua.BadTCPMessageTypeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := readReverseHello(&staticConn{buf: tt.msg}, time.Now().Add(time.Second))
			if err != tt.err {
				t.Fatalf("expected %v, got %v", tt.err, err)
			}
			if err != nil {
				return
			}
			if rc.serverURI != tt.serverURI || rc.endpointURL != tt.endpointURL {
				t.Fatalf("expected %q %q, got %q %q", tt.serverURI, tt.endpointURL, rc.serverURI, rc.endpointURL)
			}
		})
	}
}

func TestReverseConnectManagerHoldsUntilClaimedByDefault(t *testing.T) {
	mgr, err := NewReverseConnectManager(freeReverseConnectURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if mgr.holdTime != 0 {
		t.Fatalf("expected no hold limit, got %v", mgr.holdTime)
	}
	remote := dialReverseHello(t, mgr, "urn:server", "opc.tcp://127.0.0.1:4840")
	defer remote.Close()
	waitPending(t, mgr, 1)
	time.Sleep(100 * time.Millisecond)
	waitPending(t, mgr, 1)
}

func TestReverseConnectManagerDiscardsSocketClosedByServer(t *testing.T) {
	mgr := newTestReverseConnectManager(t, time.Minute)
	defer mgr.Close()

	endpointURL := "opc.tcp://127.0.0.1:4840"
	remote := dialReverseHello(t, mgr, "urn:server", endpointURL)
	waitPending(t, mgr, 1)
	remote.Close()
	waitPending(t, mgr, 0)

	ctx, cancel := timeContext(50 * time.Millisecond)
	defer cancel()
	if conn, err := mgr.Wait(ctx, endpointURL, nil); err == nil {
		conn.Close()
		t.Fatal("expected no connection after server closed the held socket")
	}
}

func TestReverseConnectManagerRejectsDataBeforeHello(t *testing.T) {
	mgr := newTestReverseConnectManager(t, time.Minute)
	defer mgr.Close()

	remote := dialReverseHello(t, mgr, "urn:server", "opc.tcp://127.0.0.1:4840")
	defer remote.Close()
	waitPending(t, mgr, 1)
	if _, err := remote.Write([]byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	expectErrorCode(t, remote, ua.BadTCPMessageTypeInvalid)
	waitPending(t, mgr, 0)
}

func TestReverseConnectManagerHelloTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		if err := WithReverseConnectHelloTimeout(d)(&ReverseConnectManager{}); err != ua.BadInvalidArgument {
			t.Errorf("%v: expected %v, got %v", d, ua.BadInvalidArgument, err)
		}
	}
	mgr, err := NewReverseConnectManager(freeReverseConnectURL(t), WithReverseConnectHelloTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	silent, err := net.Dial("tcp", mgr.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	start := time.Now()
	expectClosedWithoutError(t, silent)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("expected close after ~50ms, took %v", d)
	}
}

func TestReverseConnectManagerRejectsInvalidReverseHello(t *testing.T) {
	mgr := newTestReverseConnectManager(t, time.Second)
	defer mgr.Close()

	remote := dialReverseHello(t, mgr, strings.Repeat("u", maxReverseHelloStringLength), "opc.tcp://127.0.0.1:4840")
	defer remote.Close()
	expectErrorCode(t, remote, ua.BadTCPEndpointURLInvalid)

	other, err := net.Dial("tcp", mgr.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	msg := testReverseHelloBytes("urn:server", "opc.tcp://127.0.0.1:4840")
	binary.LittleEndian.PutUint32(msg[0:4], ua.MessageTypeHello)
	if _, err := other.Write(msg); err != nil {
		t.Fatal(err)
	}
	expectErrorCode(t, other, ua.BadTCPMessageTypeInvalid)
}

func TestReverseConnectManagerRejectsWhenTooBusy(t *testing.T) {
	reverseURL := freeReverseConnectURL(t)
	mgr, err := NewReverseConnectManager(reverseURL, WithReverseConnectMaxPending(1))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	held := dialReverseHello(t, mgr, "urn:server", "opc.tcp://127.0.0.1:4840")
	defer held.Close()
	waitPending(t, mgr, 1)

	busy, err := net.Dial("tcp", mgr.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	expectErrorCode(t, busy, badServerTooBusy)
}

func TestReverseConnectManagerClearsReadDeadline(t *testing.T) {
	mgr := newTestReverseConnectManager(t, 50*time.Millisecond)
	defer mgr.Close()

	endpointURL := "opc.tcp://127.0.0.1:4840"
	remote := dialReverseHello(t, mgr, "urn:server", endpointURL)
	defer remote.Close()
	ctx, cancel := timeContext(time.Second)
	defer cancel()
	conn, err := mgr.Wait(ctx, endpointURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	time.Sleep(150 * time.Millisecond)
	if _, err := remote.Write([]byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		t.Fatalf("expected claimed connection to outlive hold time: %v", err)
	}
}

func TestReverseConnectManagerReturnsOldestFirst(t *testing.T) {
	mgr := newTestReverseConnectManager(t, time.Second)
	defer mgr.Close()

	endpointURL := "opc.tcp://127.0.0.1:4840"
	first := dialReverseHello(t, mgr, "urn:server", endpointURL)
	defer first.Close()
	waitPending(t, mgr, 1)
	second := dialReverseHello(t, mgr, "urn:server", endpointURL)
	defer second.Close()
	waitPending(t, mgr, 2)

	ctx, cancel := timeContext(time.Second)
	defer cancel()
	conn, err := mgr.Wait(ctx, endpointURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != first.LocalAddr().String() {
		t.Fatalf("expected oldest connection %v, got %v", first.LocalAddr(), conn.RemoteAddr())
	}
}

func TestReverseConnectManagerCloseIsPrompt(t *testing.T) {
	mgr := newTestReverseConnectManager(t, time.Minute)

	silent, err := net.Dial("tcp", mgr.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	held := dialReverseHello(t, mgr, "urn:server", "opc.tcp://127.0.0.1:4840")
	defer held.Close()
	waitPending(t, mgr, 1)

	waitErr := make(chan error, 1)
	go func() {
		_, err := mgr.Wait(context.Background(), "opc.tcp://127.0.0.1:4841", nil)
		waitErr <- err
	}()

	start := time.Now()
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("expected prompt close, took %v", d)
	}
	if err := <-waitErr; err != ua.BadConnectionClosed {
		t.Fatalf("expected %v, got %v", ua.BadConnectionClosed, err)
	}
	expectClosedWithoutError(t, held)
}

func TestReverseConnectManagerHoldsIncomingConnection(t *testing.T) {
	reverseURL := freeReverseConnectURL(t)
	mgr, err := NewReverseConnectManager(
		reverseURL,
		WithReverseConnectHoldTime(time.Second),
		WithReverseConnectWaitTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	endpointURL := "opc.tcp://127.0.0.1:4840"
	remote := dialReverseHello(t, mgr, "urn:server", endpointURL)
	defer remote.Close()

	time.Sleep(25 * time.Millisecond)
	ctx, cancel := timeContext(time.Second)
	defer cancel()
	conn, err := mgr.Wait(ctx, endpointURL, []string{"urn:server"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := remote.Write([]byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x7f {
		t.Fatalf("expected 0x7f, got 0x%x", buf[0])
	}
}

func TestReverseConnectManagerMatchesEndpointAndServerURI(t *testing.T) {
	reverseURL := freeReverseConnectURL(t)
	mgr, err := NewReverseConnectManager(
		reverseURL,
		WithReverseConnectHoldTime(time.Second),
		WithReverseConnectWaitTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	remoteA := dialReverseHello(t, mgr, "urn:a", "opc.tcp://127.0.0.1:4840")
	defer remoteA.Close()
	remoteB := dialReverseHello(t, mgr, "urn:b", "opc.tcp://127.0.0.1:4841")
	defer remoteB.Close()

	ctx, cancel := timeContext(time.Second)
	defer cancel()
	conn, err := mgr.Wait(ctx, "opc.tcp://127.0.0.1:4841", []string{"urn:b"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := remoteB.Write([]byte{0x42}); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x42 {
		t.Fatalf("expected 0x42, got 0x%x", buf[0])
	}
}

func TestReverseConnectManagerClosesUnclaimedConnectionAfterHoldTime(t *testing.T) {
	mgr := newTestReverseConnectManager(t, 25*time.Millisecond)
	defer mgr.Close()

	remote := dialReverseHello(t, mgr, "urn:server", "opc.tcp://127.0.0.1:4840")
	defer remote.Close()
	expectClosedWithoutError(t, remote)
}

func BenchmarkReadReverseHello(b *testing.B) {
	msg := testReverseHelloBytes("urn:server", "opc.tcp://127.0.0.1:4840")
	deadline := time.Now().Add(time.Hour)
	conn := &staticConn{buf: msg}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.off = 0
		if _, err := readReverseHello(conn, deadline); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteReverseReject(b *testing.B) {
	conn := discardConn{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := writeReverseReject(conn, ua.BadTCPMessageTypeInvalid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReverseConnectionMatches(b *testing.B) {
	rc := &reverseConnection{serverURI: "urn:server", endpointURL: "opc.tcp://127.0.0.1:4840"}
	serverURIs := []string{"urn:other", "urn:server"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !reverseConnectionMatches(rc, "opc.tcp://127.0.0.1:4840", serverURIs) {
			b.Fatal("expected match")
		}
	}
}

func writeTestReverseHello(t *testing.T, conn net.Conn, serverURI, endpointURL string) {
	t.Helper()
	buf := testReverseHelloBytes(serverURI, endpointURL)
	if _, err := conn.Write(buf); err != nil {
		t.Error(err)
	}
}

func testReverseHelloBytes(serverURI, endpointURL string) []byte {
	msgLen := 16 + len(serverURI) + len(endpointURL)
	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], ua.MessageTypeReverseHello)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(serverURI)))
	copy(buf[12:12+len(serverURI)], serverURI)
	offset := 12 + len(serverURI)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(len(endpointURL)))
	copy(buf[offset+4:], endpointURL)
	return buf
}

func newTestReverseConnectManager(t *testing.T, holdTime time.Duration) *ReverseConnectManager {
	t.Helper()
	mgr, err := NewReverseConnectManager(
		freeReverseConnectURL(t),
		WithReverseConnectHoldTime(holdTime),
		WithReverseConnectWaitTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func waitPending(t *testing.T, mgr *ReverseConnectManager, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		got := len(mgr.pending)
		mgr.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected %d pending connections", n)
}

func expectErrorCode(t *testing.T, conn net.Conn, want ua.StatusCode) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	code, err := readTestErrorCode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if code != want {
		t.Fatalf("expected %v, got %v", want, code)
	}
}

func expectClosedWithoutError(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if n, err := conn.Read(buf[:]); err != io.EOF {
		t.Fatalf("expected close without Error message, got n=%d err=%v", n, err)
	}
}

func readTestErrorCode(conn net.Conn) (ua.StatusCode, error) {
	var buf [16]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != ua.MessageTypeError {
		return 0, ua.BadTCPMessageTypeInvalid
	}
	return ua.StatusCode(binary.LittleEndian.Uint32(buf[8:12])), nil
}

func freeReverseConnectURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "opc.tcp://" + addr
}

func dialReverseHello(t *testing.T, mgr *ReverseConnectManager, serverURI, endpointURL string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", mgr.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	writeTestReverseHello(t, conn, serverURI, endpointURL)
	return conn
}

func timeContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

type staticConn struct {
	buf []byte
	off int
}

func (c *staticConn) Close() error                     { return nil }
func (c *staticConn) LocalAddr() net.Addr              { return testAddr{} }
func (c *staticConn) RemoteAddr() net.Addr             { return testAddr{} }
func (c *staticConn) SetDeadline(time.Time) error      { return nil }
func (c *staticConn) SetReadDeadline(time.Time) error  { return nil }
func (c *staticConn) SetWriteDeadline(time.Time) error { return nil }
func (c *staticConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *staticConn) Read(p []byte) (int, error) {
	if c.off >= len(c.buf) {
		return 0, io.EOF
	}
	n := copy(p, c.buf[c.off:])
	c.off += n
	return n, nil
}
func (c discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c discardConn) Close() error                     { return nil }
func (c discardConn) LocalAddr() net.Addr              { return testAddr{} }
func (c discardConn) RemoteAddr() net.Addr             { return testAddr{} }
func (c discardConn) SetDeadline(time.Time) error      { return nil }
func (c discardConn) SetReadDeadline(time.Time) error  { return nil }
func (c discardConn) SetWriteDeadline(time.Time) error { return nil }
func (a testAddr) Network() string                     { return "test" }
func (a testAddr) String() string                      { return "test" }

type discardConn struct{}

type testAddr struct{}
