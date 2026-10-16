// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
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
// previous one closes. Before every dial it waits: the minimum delay after a socket that ended
// well, or a delay that doubles up to the maximum after a failure. A socket ended well when the
// client opened a secure channel on it, or sent nothing at all before it closed (a client that
// had no session to open). A failure is a dial that failed, or a peer that sent bytes that did not
// open a secure channel (a service on a mistyped port), which is backed off like an unreachable one.
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
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err == nil {
			err = srv.serveReverseConnection(ctx, clientURL, conn, wg)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			srv.reportReverseConnect(clientURL, err)
		} else {
			delay = reverseConnectMinDelay
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		if err != nil {
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
// It returns nil when the connection ended well, or the failure that ended it.
func (srv *Server) serveReverseConnection(ctx context.Context, clientURL string, conn net.Conn, wg *sync.WaitGroup) error {
	if err := srv.writeReverseHello(conn); err != nil {
		conn.Close()
		return err
	}
	var openErr error
	opened := func(err error) {
		openErr = err
		if err == nil {
			srv.reportReverseConnect(clientURL, nil)
		}
	}
	done := make(chan struct{})
	wg.Add(1)
	rc := &reverseConn{Conn: conn}
	go func() {
		defer close(done)
		srv.serveConnection(rc, wg, opened)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// do not wait for the Hello timeout of an unused socket.
		conn.Close()
		<-done
	}
	if openErr != nil && rc.spoke.Load() {
		return fmt.Errorf("the client did not open a secure channel: %w", openErr)
	}
	return nil
}

// writeReverseHello writes a ReverseHello message to the connection.
func (srv *Server) writeReverseHello(conn net.Conn) error {
	serverURI := srv.localDescription.ApplicationURI
	endpointURL := reverseHelloEndpointURL(srv.endpointURL, conn.LocalAddr())
	var buf bytes.Buffer
	enc := ua.NewBinaryEncoder(&buf, ua.NewEncodingContext())
	enc.WriteUInt32(ua.MessageTypeReverseHello)
	enc.WriteUInt32(uint32(16 + len(serverURI) + len(endpointURL)))
	enc.WriteString(serverURI)
	enc.WriteString(endpointURL)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	_, err := conn.Write(buf.Bytes())
	return err
}

// reverseHelloEndpointURL is the EndpointUrl a ReverseHello sent from local carries.
// A server bound to every interface (opc.tcp://0.0.0.0:port, opc.tcp://[::]:port) has an
// endpoint URL that no client can dial, so its host is replaced by the address the reverse
// socket left from: the address of this server that the client reaches, and the one a
// GetEndpoints request over it is answered with. Any other endpoint URL is sent unchanged.
func reverseHelloEndpointURL(endpointURL string, local net.Addr) string {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return endpointURL
	}
	if ip := net.ParseIP(u.Hostname()); u.Hostname() != "" && (ip == nil || !ip.IsUnspecified()) {
		return endpointURL
	}
	tcp, ok := local.(*net.TCPAddr)
	if !ok || tcp.IP == nil || tcp.IP.IsUnspecified() {
		return endpointURL
	}
	u.Host = net.JoinHostPort(tcp.IP.String(), u.Port())
	return u.String()
}

// reverseConn records whether the peer sent anything.
type reverseConn struct {
	net.Conn
	spoke atomic.Bool
}

func (c *reverseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.spoke.Store(true)
	}
	return n, err
}
