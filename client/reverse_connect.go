// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
)

var reverseHelloBufferPool = sync.Pool{New: func() any {
	buf := make([]byte, maxReverseHelloSize)
	return &buf
}}

var reverseRejectBufferPool = sync.Pool{New: func() any {
	return new([16]byte)
}}

// badServerTooBusy is Bad_ServerTooBusy, which Part 6 §7.1.3 requires; ua predates it.
const badServerTooBusy ua.StatusCode = 0x80EE0000

const (
	defaultReverseConnectWaitTimeout  = 20 * time.Second
	defaultReverseConnectMaxPending   = 64
	defaultReverseConnectHelloTimeout = 10 * time.Second
	maxReverseHelloStringLength       = 4096
	maxReverseHelloSize               = 16 + 2*(maxReverseHelloStringLength-1)
)

// ReverseConnectManager accepts ReverseHello messages and holds matching connections for clients.
// A shared manager keeps the listener open between dial attempts, so the socket a server keeps
// waiting for the client is available immediately.
type ReverseConnectManager struct {
	endpointURL  string
	ln           net.Listener
	holdTime     time.Duration
	helloTimeout time.Duration
	waitTimeout  time.Duration
	maxPending   int

	closeOnce sync.Once
	wg        sync.WaitGroup

	mu          sync.Mutex
	active      int
	handshaking []net.Conn
	pending     []*reverseConnection
	waiters     int
	notify      chan struct{}
	closing     chan struct{}
	closed      chan struct{}
	err         error
}

// ReverseConnectManagerOption configures a ReverseConnectManager.
type ReverseConnectManagerOption func(*ReverseConnectManager) error

type reverseConnection struct {
	conn        net.Conn
	serverURI   string
	endpointURL string
	monitor     sync.WaitGroup
	err         error
	probe       [1]byte
}

// WithReverseConnectHoldTime limits how long an unclaimed ReverseHello socket is held.
// By default sockets are held until claimed or closed by the server.
func WithReverseConnectHoldTime(value time.Duration) ReverseConnectManagerOption {
	return func(m *ReverseConnectManager) error {
		if value > 0 {
			m.holdTime = value
		}
		return nil
	}
}

// WithReverseConnectHelloTimeout sets how long an incoming socket may wait for ReverseHello before it is closed. (default: 10s)
func WithReverseConnectHelloTimeout(value time.Duration) ReverseConnectManagerOption {
	return func(m *ReverseConnectManager) error {
		if value <= 0 {
			return ua.BadInvalidArgument
		}
		m.helloTimeout = value
		return nil
	}
}

// WithReverseConnectWaitTimeout sets how long Wait waits for a matching ReverseHello socket.
func WithReverseConnectWaitTimeout(value time.Duration) ReverseConnectManagerOption {
	return func(m *ReverseConnectManager) error {
		if value > 0 {
			m.waitTimeout = value
		}
		return nil
	}
}

// WithReverseConnectMaxPending sets how many incoming sockets may be held or awaiting ReverseHello.
// Further sockets are rejected with Bad_ServerTooBusy. The default is 64.
func WithReverseConnectMaxPending(value int) ReverseConnectManagerOption {
	return func(m *ReverseConnectManager) error {
		if value > 0 {
			m.maxPending = value
		}
		return nil
	}
}

// NewReverseConnectManager listens at reverseURL and accepts reverse connections.
func NewReverseConnectManager(reverseURL string, opts ...ReverseConnectManagerOption) (*ReverseConnectManager, error) {
	ln, err := listenReverse(reverseURL)
	if err != nil {
		return nil, err
	}
	m := &ReverseConnectManager{
		endpointURL:  reverseURL,
		ln:           ln,
		helloTimeout: defaultReverseConnectHelloTimeout,
		waitTimeout:  defaultReverseConnectWaitTimeout,
		maxPending:   defaultReverseConnectMaxPending,
		notify:       make(chan struct{}),
		closing:      make(chan struct{}),
		closed:       make(chan struct{}),
	}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			ln.Close()
			return nil, err
		}
	}
	go m.serve()
	return m, nil
}

// EndpointURL returns the reverse connect endpoint URL.
func (m *ReverseConnectManager) EndpointURL() string {
	if m == nil {
		return ""
	}
	return m.endpointURL
}

// Addr returns the listener network address.
func (m *ReverseConnectManager) Addr() net.Addr {
	if m == nil || m.ln == nil {
		return nil
	}
	return m.ln.Addr()
}

// Close stops the manager and closes any held reverse connections.
func (m *ReverseConnectManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		close(m.closing)
		err := m.ln.Close()
		m.mu.Lock()
		if m.err == nil && err != nil && !isClosedNetworkError(err) {
			m.err = err
		}
		pending := m.pending
		handshaking := m.handshaking
		m.pending = nil
		m.handshaking = nil
		m.active -= len(pending)
		m.mu.Unlock()
		for _, rc := range pending {
			rc.conn.Close()
		}
		for _, conn := range handshaking {
			conn.Close()
		}
		m.wg.Wait()
		close(m.closed)
	})
	<-m.closed
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// Wait returns a held reverse connection matching endpointURL and serverURIs.
// Held connections are returned oldest first.
func (m *ReverseConnectManager) Wait(ctx context.Context, endpointURL string, serverURIs []string) (net.Conn, error) {
	if m == nil {
		return nil, ua.BadConnectionClosed
	}
	if m.waitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.waitTimeout)
		defer cancel()
	}
	m.mu.Lock()
	for {
		if rc := m.takeLocked(endpointURL, serverURIs); rc != nil {
			m.mu.Unlock()
			if conn, err := claim(rc); err == nil {
				return conn, nil
			}
			m.mu.Lock()
			continue
		}
		select {
		case <-m.closing:
			err := m.err
			m.mu.Unlock()
			if err == nil {
				err = ua.BadConnectionClosed
			}
			return nil, err
		default:
		}
		notify := m.notify
		m.waiters++
		m.mu.Unlock()
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-notify:
		case <-m.closing:
		}
		m.mu.Lock()
		m.waiters--
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
	}
}

func (m *ReverseConnectManager) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.closing:
				return
			default:
				m.fail(err)
				return
			}
		}
		m.mu.Lock()
		select {
		case <-m.closing:
			m.mu.Unlock()
			conn.Close()
			return
		default:
		}
		if m.active >= m.maxPending {
			m.mu.Unlock()
			_ = writeReverseReject(conn, badServerTooBusy)
			conn.Close()
			continue
		}
		m.active++
		m.handshaking = append(m.handshaking, conn)
		m.wg.Add(1)
		m.mu.Unlock()
		go m.handle(conn)
	}
}

func (m *ReverseConnectManager) handle(conn net.Conn) {
	defer m.wg.Done()
	rc, err := readReverseHello(conn, time.Now().Add(m.helloTimeout))
	if err == nil {
		var holdDeadline time.Time
		if m.holdTime > 0 {
			holdDeadline = time.Now().Add(m.holdTime)
		}
		// set before the socket is visible to Wait, so claim's deadline always wins.
		err = conn.SetReadDeadline(holdDeadline)
	}
	m.mu.Lock()
	tracked := removeConn(&m.handshaking, conn)
	if err != nil || !tracked {
		if tracked {
			m.active--
		}
		m.mu.Unlock()
		if code, ok := err.(ua.StatusCode); ok {
			_ = writeReverseReject(conn, code)
		}
		conn.Close()
		return
	}
	rc.conn = conn
	rc.monitor.Add(1)
	m.pending = append(m.pending, rc)
	m.notifyLocked()
	m.mu.Unlock()
	m.monitor(rc)
}

// monitor watches a held socket so one closed by the server, or past its hold time, is discarded.
// The server sends nothing until Hello, so any data is a protocol violation.
func (m *ReverseConnectManager) monitor(rc *reverseConnection) {
	defer rc.monitor.Done()
	n, _ := rc.conn.Read(rc.probe[:])
	m.mu.Lock()
	removed := false
	for i, pending := range m.pending {
		if pending == rc {
			m.removePendingLocked(i)
			removed = true
			break
		}
	}
	m.mu.Unlock()
	if !removed {
		if n > 0 {
			rc.err = ua.BadTCPMessageTypeInvalid
		}
		return
	}
	if n > 0 {
		_ = writeReverseReject(rc.conn, ua.BadTCPMessageTypeInvalid)
	}
	rc.conn.Close()
}

// claim stops the monitor of a socket taken from pending and returns the socket ready for Hello.
func claim(rc *reverseConnection) (net.Conn, error) {
	_ = rc.conn.SetReadDeadline(time.Now())
	rc.monitor.Wait()
	if rc.err == nil {
		rc.err = rc.conn.SetReadDeadline(time.Time{})
	}
	if rc.err != nil {
		if rc.err == ua.BadTCPMessageTypeInvalid {
			_ = writeReverseReject(rc.conn, ua.BadTCPMessageTypeInvalid)
		}
		rc.conn.Close()
		return nil, rc.err
	}
	return rc.conn, nil
}

func (m *ReverseConnectManager) fail(err error) {
	m.mu.Lock()
	if m.err == nil && !isClosedNetworkError(err) {
		m.err = err
	}
	m.mu.Unlock()
	m.Close()
}

func (m *ReverseConnectManager) takeLocked(endpointURL string, serverURIs []string) *reverseConnection {
	for i, rc := range m.pending {
		if reverseConnectionMatches(rc, endpointURL, serverURIs) {
			m.removePendingLocked(i)
			return rc
		}
	}
	return nil
}

func (m *ReverseConnectManager) removePendingLocked(i int) {
	last := len(m.pending) - 1
	copy(m.pending[i:], m.pending[i+1:])
	m.pending[last] = nil
	m.pending = m.pending[:last]
	m.active--
}

func (m *ReverseConnectManager) notifyLocked() {
	if m.waiters == 0 {
		return
	}
	close(m.notify)
	m.notify = make(chan struct{})
}

func removeConn(conns *[]net.Conn, conn net.Conn) bool {
	s := *conns
	for i, c := range s {
		if c == conn {
			last := len(s) - 1
			s[i] = s[last]
			s[last] = nil
			*conns = s[:last]
			return true
		}
	}
	return false
}

func reverseConnectionMatches(rc *reverseConnection, endpointURL string, serverURIs []string) bool {
	if endpointURL != "" && rc.endpointURL != endpointURL {
		return false
	}
	if len(serverURIs) == 0 {
		return true
	}
	for _, serverURI := range serverURIs {
		if rc.serverURI == serverURI {
			return true
		}
	}
	return false
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

func listenReverse(reverseURL string) (net.Listener, error) {
	u, err := url.Parse(reverseURL)
	if err != nil {
		return nil, err
	}
	return net.Listen("tcp", u.Host)
}

func reverseConnectDuration(value int64) time.Duration {
	if value <= 0 {
		value = defaultConnectTimeout
	}
	return time.Duration(value) * time.Millisecond
}

func getEndpointsReverse(ctx context.Context, request *ua.GetEndpointsRequest, manager *ReverseConnectManager, endpointURL string, serverURIs []string, connectTimeout int64) (*ua.GetEndpointsResponse, error) {
	ch := newClientSecureChannel(
		ua.ApplicationDescription{
			ApplicationName: ua.LocalizedText{Text: "DiscoveryClient"},
			ApplicationType: ua.ApplicationTypeClient,
		},
		nil,
		nil,
		request.EndpointURL,
		ua.SecurityPolicyURINone,
		ua.MessageSecurityModeNone,
		nil,
		connectTimeout,
		"",
		"",
		"",
		"",
		"",
		false,
		false,
		false,
		false,
		defaultTimeoutHint,
		defaultDiagnosticsHint,
		defaultTokenRequestedLifetime,
		defaultMaxBufferSize,
		defaultMaxMessageSize,
		defaultMaxChunkCount,
		false,
	)
	conn, err := manager.Wait(ctx, endpointURL, serverURIs)
	if err != nil {
		return nil, err
	}
	ch.conn = conn

	if err := ch.Open(ctx); err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	res, err := ch.GetEndpoints(ctx, request)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	err = ch.Close(ctx)
	if err != nil {
		ch.Abort(ctx)
		return nil, err
	}
	return res, nil
}

// readReverseHello reads a ReverseHello and copies both strings with one allocation.
func readReverseHello(conn net.Conn, deadline time.Time) (*reverseConnection, error) {
	_ = conn.SetReadDeadline(deadline)
	bufp := reverseHelloBufferPool.Get().(*[]byte)
	defer reverseHelloBufferPool.Put(bufp)
	header := (*bufp)[:8]
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(header[:4]) != ua.MessageTypeReverseHello {
		return nil, ua.BadTCPMessageTypeInvalid
	}
	msgLen := binary.LittleEndian.Uint32(header[4:8])
	if msgLen < 16 {
		return nil, ua.BadDecodingError
	}
	if msgLen > maxReverseHelloSize {
		return nil, ua.BadTCPEndpointURLInvalid
	}
	buf := (*bufp)[8:msgLen]
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	n1, err := readReverseHelloStringLength(buf)
	if err != nil {
		return nil, err
	}
	n2, err := readReverseHelloStringLength(buf[4+n1:])
	if err != nil {
		return nil, err
	}
	s := string(buf[4 : 8+n1+n2])
	return &reverseConnection{serverURI: s[:n1], endpointURL: s[n1+4:]}, nil
}

// readReverseHelloStringLength returns the length of the String at the start of buf; null is empty.
func readReverseHelloStringLength(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, ua.BadDecodingError
	}
	n := int(int32(binary.LittleEndian.Uint32(buf[:4])))
	if n < 0 {
		n = 0
	}
	if n >= maxReverseHelloStringLength {
		return 0, ua.BadTCPEndpointURLInvalid
	}
	if n > len(buf)-4 {
		return 0, ua.BadDecodingError
	}
	return n, nil
}

func writeReverseReject(conn net.Conn, code ua.StatusCode) error {
	bufp := reverseRejectBufferPool.Get().(*[16]byte)
	defer reverseRejectBufferPool.Put(bufp)
	buf := bufp[:]
	binary.LittleEndian.PutUint32(buf[0:4], ua.MessageTypeError)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(16))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(code))
	binary.LittleEndian.PutUint32(buf[12:16], 0xFFFFFFFF)
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Write(buf)
	return err
}
