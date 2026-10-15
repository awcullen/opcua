// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"context"
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
func (srv *Server) reverseConnect(clientURL string, wg *sync.WaitGroup) {
	defer wg.Done()
	u, err := url.Parse(clientURL)
	if err != nil {
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
		inUse := false
		conn, err := dialer.DialContext(ctx, "tcp", u.Host)
		if err == nil {
			inUse = srv.serveReverseConnection(ctx, conn, wg)
		}
		if ctx.Err() != nil {
			return
		}
		if inUse {
			// the client is using the socket, so open the next one now.
			delay = reverseConnectMinDelay
			continue
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		delay *= 2
		if delay > reverseConnectMaxDelay {
			delay = reverseConnectMaxDelay
		}
	}
}

// serveReverseConnection sends the ReverseHello and hands the connection to handleConnection.
// It returns true when the client starts using the connection, or false when the connection
// closes before the client sends a Hello.
func (srv *Server) serveReverseConnection(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) bool {
	if err := srv.writeReverseHello(conn); err != nil {
		conn.Close()
		return false
	}
	rc := &reverseConn{Conn: conn, used: make(chan struct{})}
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer close(done)
		srv.handleConnection(rc, wg)
	}()
	select {
	case <-rc.used:
		return true
	case <-done:
		return false
	case <-ctx.Done():
		// the client never used this socket; do not wait for the Hello timeout.
		conn.Close()
		<-done
		return false
	}
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

// reverseConn signals when the client sends its first message.
type reverseConn struct {
	net.Conn
	once sync.Once
	used chan struct{}
}

func (c *reverseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { close(c.used) })
	}
	return n, err
}
