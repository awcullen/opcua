// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
)

var (
	// reverseConnectMinDelay is the wait before reconnecting after a failed connection.
	// It doubles after each consecutive failure, up to reverseConnectMaxDelay.
	reverseConnectMinDelay = 1 * time.Second
	reverseConnectMaxDelay = 30 * time.Second
)

// reverseConnect keeps one socket open to the client at clientURL, until the server is closed.
// See https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.3
//
// It holds at most one socket to the client at a time: the next one is opened only after the
// previous one closes. Before every dial it waits: the minimum delay after a socket the client
// used, or a delay that doubles up to the maximum after one it did not. A socket counts as used
// only when the client opened a secure channel on it, so a peer that answers with something else
// (a service on a mistyped port) is backed off like an unreachable one.
func (srv *Server) reverseConnect(clientURL string, wg *sync.WaitGroup) {
	defer wg.Done()
	u, err := url.Parse(clientURL)
	if err != nil {
		srv.reportReverseConnect(clientURL, err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-srv.closing:
			cancel()
		case <-ctx.Done():
		}
	}()

	var dialer net.Dialer
	delay := reverseConnectMinDelay
	for {
		used := false
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err == nil {
			used, err = srv.serveReverseConnection(ctx, clientURL, conn, wg)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			srv.reportReverseConnect(clientURL, err)
		}
		if used {
			delay = reverseConnectMinDelay
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		if !used {
			delay *= 2
			if delay > reverseConnectMaxDelay {
				delay = reverseConnectMaxDelay
			}
		}
	}
}

// reportReverseConnect calls the function set by WithReverseConnectStateFunc, if any.
func (srv *Server) reportReverseConnect(clientURL string, err error) {
	if srv.reverseConnectStateFunc != nil {
		srv.reverseConnectStateFunc(clientURL, err)
	}
}

// serveReverseConnection sends the ReverseHello and serves the connection until it closes.
// It returns whether the client opened a secure channel on it, and the error that ended an
// unused connection.
func (srv *Server) serveReverseConnection(ctx context.Context, clientURL string, conn net.Conn, wg *sync.WaitGroup) (bool, error) {
	if err := srv.writeReverseHello(conn); err != nil {
		conn.Close()
		return false, err
	}
	srv.reportReverseConnect(clientURL, nil)
	var openErr error
	opened := func(err error) {
		openErr = err
	}
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer close(done)
		srv.serveConnection(conn, wg, opened)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// do not wait for the Hello timeout of an unused socket.
		conn.Close()
		<-done
	}
	if openErr != nil {
		return false, fmt.Errorf("the client did not open a secure channel: %w", openErr)
	}
	return true, nil
}

// writeReverseHello writes a ReverseHello message to the connection.
func (srv *Server) writeReverseHello(conn net.Conn) error {
	serverURI := srv.localDescription.ApplicationURI
	var buf bytes.Buffer
	enc := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	enc.WriteUInt32(ua.MessageTypeReverseHello)
	enc.WriteUInt32(uint32(16 + len(serverURI) + len(srv.endpointURL)))
	enc.WriteString(serverURI)
	enc.WriteString(srv.endpointURL)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	_, err := conn.Write(buf.Bytes())
	return err
}
