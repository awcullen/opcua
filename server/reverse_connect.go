// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
)

const (
	maxReverseHelloStringLength = 4096
	reverseConnectMinRedialAge  = time.Second
)

// helloTimeout is how long an incoming connection may wait for Hello and OpenSecureChannel.
var helloTimeout = 20 * time.Second

// reverseConnectTarget tracks the sockets the server holds open to one reverse connect client.
type reverseConnectTarget struct {
	host          string
	pending       int
	established   int
	rejectedUntil time.Time
}

// remoteError is an Error message received from the peer.
type remoteError ua.StatusCode

func (e remoteError) Error() string {
	return ua.StatusCode(e).Error()
}

func validReverseHelloStrings(serverURI, endpointURL string) bool {
	return len(serverURI) < maxReverseHelloStringLength && len(endpointURL) < maxReverseHelloStringLength
}

func (srv *Server) reverseConnect(wg *sync.WaitGroup) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-srv.closing:
			cancel()
		case <-ctx.Done():
		}
	}()

	ticker := time.NewTicker(srv.reverseConnectInterval)
	defer ticker.Stop()
	for {
		srv.reverseConnectOnce(ctx, wg)
		select {
		case <-srv.closing:
			return
		case <-ticker.C:
		case <-srv.reverseConnectKick:
		}
	}
}

func (srv *Server) reverseConnectOnce(ctx context.Context, wg *sync.WaitGroup) {
	now := time.Now()
	for i := range srv.reverseConnectTargets {
		t := &srv.reverseConnectTargets[i]
		if !srv.beginReverseConnect(t, now) {
			continue
		}
		wg.Add(1)
		go srv.dialReverseConnect(ctx, wg, t)
	}
}

func (srv *Server) dialReverseConnect(ctx context.Context, wg *sync.WaitGroup, t *reverseConnectTarget) {
	dialCtx, cancel := context.WithTimeout(ctx, srv.reverseConnectTimeout)
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", t.host)
	cancel()
	if err != nil {
		srv.endReverseConnect(t, false)
		wg.Done()
		return
	}
	srv.handleReverseConnection(conn, wg, t)
}

// beginReverseConnect reports whether a new socket should be opened to the client.
// Part 6 requires one socket without an active SecureChannel per client.
func (srv *Server) beginReverseConnect(t *reverseConnectTarget, now time.Time) bool {
	srv.reverseConnectMu.Lock()
	defer srv.reverseConnectMu.Unlock()
	if t.pending > 0 || now.Before(t.rejectedUntil) {
		return false
	}
	t.pending++
	return true
}

// establishReverseConnect marks a pending socket as used by a SecureChannel and requests a replacement.
func (srv *Server) establishReverseConnect(t *reverseConnectTarget) {
	srv.reverseConnectMu.Lock()
	t.pending--
	t.established++
	srv.reverseConnectMu.Unlock()
	srv.kickReverseConnect()
}

func (srv *Server) endReverseConnect(t *reverseConnectTarget, established bool) {
	srv.reverseConnectMu.Lock()
	if established {
		t.established--
	} else {
		t.pending--
	}
	srv.reverseConnectMu.Unlock()
	if established {
		srv.kickReverseConnect()
	}
}

func (srv *Server) rejectReverseConnect(t *reverseConnectTarget, now time.Time) {
	srv.reverseConnectMu.Lock()
	t.rejectedUntil = now.Add(srv.reverseConnectRejectTimeout)
	srv.reverseConnectMu.Unlock()
}

func (srv *Server) kickReverseConnect() {
	select {
	case srv.reverseConnectKick <- struct{}{}:
	default:
	}
}
