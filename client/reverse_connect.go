// Copyright 2021 Converter Systems LLC. All rights reserved.

package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/awcullen/opcua/ua"
)

// Dialer opens a connection to the server at the given address.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// maxReverseHelloLength limits the ReverseHello message: ServerUri and EndpointUrl are each at most 4096 bytes.
const maxReverseHelloLength = 8 + 4 + 4096 + 4 + 4096

// ReverseConnectDialer returns a Dialer that accepts connections from a server using reverse connect,
// as defined in https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.3
// Each call accepts the next connection from the listener and reads its ReverseHello message.
// A connection whose ReverseHello does not name the requested endpointURL is closed and skipped.
// Use it with WithDialer, passing the server's endpoint URL to Dial as usual.
func ReverseConnectDialer(ln net.Listener, endpointURL string) Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		for {
			conn, err := acceptContext(ctx, ln)
			if err != nil {
				return nil, err
			}
			_, serverEndpointURL, err := ReadReverseHello(conn)
			if err != nil || serverEndpointURL != endpointURL {
				conn.Close()
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			return conn, nil
		}
	}
}

// ReadReverseHello reads the ReverseHello message that a server sends first on a reverse connection.
func ReadReverseHello(conn net.Conn) (serverURI, endpointURL string, err error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var header [8]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", "", err
	}
	ec := ua.NewEncodingContext()
	dec := ua.NewBinaryDecoder(bytes.NewReader(header[:]), ec)
	var msgType, msgLen uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return "", "", err
	}
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return "", "", err
	}
	if msgType != ua.MessageTypeReverseHello || msgLen < 16 || msgLen > maxReverseHelloLength {
		return "", "", ua.BadTCPMessageTypeInvalid
	}
	body := make([]byte, msgLen-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", "", err
	}
	dec = ua.NewBinaryDecoder(bytes.NewReader(body), ec)
	if err := dec.ReadString(&serverURI); err != nil {
		return "", "", err
	}
	if err := dec.ReadString(&endpointURL); err != nil {
		return "", "", err
	}
	return serverURI, endpointURL, nil
}

// acceptContext accepts the next connection from the listener, or returns when the context is done.
func acceptContext(ctx context.Context, ln net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
