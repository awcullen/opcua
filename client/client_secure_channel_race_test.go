package client_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
)

// TestAbortWhileConnectionIsReset aborts a client while its connection is
// reset by the peer. Close and Abort set clientSecureChannel.closing under the
// channel mutex; responseWorker reads it without that mutex when the read
// fails. Run with -race: while closing was a plain bool, the race detector
// reported a data race between Abort and responseWorker.
func TestAbortWhileConnectionIsReset(t *testing.T) {
	ctx := context.Background()
	proxy := startResetProxy(t, strings.TrimPrefix(endpointURL, "opc.tcp://"))
	for i := 0; i < 10; i++ {
		ch := dialWhenReady(ctx, t, "opc.tcp://"+proxy.listener.Addr().String())
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.reset()
		}()
		_ = ch.Abort(ctx) // the connection may already be gone; only the race matters
		wg.Wait()
	}
}

// dialWhenReady retries the dial for up to 10 s: TestMain starts the test
// server in a goroutine and does not wait until it listens.
func dialWhenReady(ctx context.Context, t *testing.T, url string) *client.Client {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ch, err := client.Dial(ctx, url, client.WithInsecureSkipVerify())
		if err == nil {
			return ch
		}
		if time.Now().After(deadline) {
			t.Fatalf("Error connecting to server: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// resetProxy forwards TCP connections to target. reset() ends every open
// connection with an RST (SO_LINGER 0), like a network reset.
type resetProxy struct {
	listener net.Listener
	target   string
	mu       sync.Mutex
	conns    []*net.TCPConn
}

func startResetProxy(t *testing.T, target string) *resetProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &resetProxy{listener: l, target: target}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c.(*net.TCPConn), u.(*net.TCPConn))
			p.mu.Unlock()
			go func() { _, _ = io.Copy(u, c) }()
			go func() { _, _ = io.Copy(c, u) }()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		p.reset()
	})
	return p
}

func (p *resetProxy) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.SetLinger(0)
		_ = c.Close()
	}
	p.conns = nil
}
