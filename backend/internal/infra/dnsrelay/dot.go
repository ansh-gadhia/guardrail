package dnsrelay

import (
	"context"
	"errors"
	"net"
	"time"
)

// TLSServer answers DNS over TLS (RFC 7858) from an ordinary resolver: the
// TCP framing of ordinary DNS, inside TLS. Each query goes on to the resolver
// over TCP, as Server's do.
type TLSServer struct {
	// Backend is the resolver's host:port.
	Backend string
	// Timeout bounds one query. Zero means five seconds.
	Timeout time.Duration
	// Idle is how long a connection may wait for its next query — and how long
	// a new one has to finish the TLS handshake. Zero means 30 seconds. RFC 7766
	// asks servers to let clients reuse a connection; it does not ask them to
	// hold one open for ever.
	Idle time.Duration
	// MaxConns caps the connections open at once. One past it is closed
	// straight away rather than queued, so a flood of idle connections cannot
	// take every file descriptor. Zero means 1024.
	MaxConns int
}

// Serve answers connections on ln — a TLS listener — until ctx ends.
func (s *TLSServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	slots := make(chan struct{}, s.maxConns())
	backoff := time.Duration(0)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of file descriptors, say: wait and try again, as net/http
			// does, rather than take DNS down over a moment's pressure.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			serveFrames(ctx, conn, s.idle(), s.exchange)
		}()
	}
}

func (s *TLSServer) exchange(ctx context.Context, q []byte) []byte {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	resp, err := ExchangeTCP(ctx, s.Backend, q)
	if err != nil {
		// Answered, not dropped: a client waiting on a silent connection sits
		// out its own timeout before trying anything else.
		return ServFail(q)
	}
	return resp
}

func (s *TLSServer) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 5 * time.Second
}

func (s *TLSServer) idle() time.Duration {
	if s.Idle > 0 {
		return s.Idle
	}
	return 30 * time.Second
}

func (s *TLSServer) maxConns() int {
	if s.MaxConns > 0 {
		return s.MaxConns
	}
	return 1024
}
