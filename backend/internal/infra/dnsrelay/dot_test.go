package dnsrelay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// startDoT runs s on a TLS listener with a throwaway certificate, and returns
// its address and a client config that trusts that certificate.
func startDoT(t *testing.T, s *TLSServer) (string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "guardrail-test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(tcp, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v after shutdown, want nil", err)
		}
	})
	return tcp.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "127.0.0.1"}
}

func TestTLSServer_AnswersSeveralQueriesOnOneConnection(t *testing.T) {
	addr, conf := startDoT(t, &TLSServer{Backend: fakeResolver(t)})
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Reusing the connection is the point of RFC 7766: three queries, one
	// handshake, answered in order and each matched by its ID.
	for id := uint16(7); id < 10; id++ {
		if err := writeFrame(conn, query(id, "db1.tunnel.guardrail.lan", 0)); err != nil {
			t.Fatal(err)
		}
		resp, err := readFrame(conn)
		if err != nil {
			t.Fatalf("query %d: %v", id, err)
		}
		if binary.BigEndian.Uint16(resp) != id || resp[2]&flagQR == 0 || binary.BigEndian.Uint16(resp[6:]) != 2 {
			t.Fatalf("query %d: not the resolver's answer: % x", id, resp[:12])
		}
	}
}

func TestTLSServer_AnswersServFailWhenTheResolverIsDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	addr, conf := startDoT(t, &TLSServer{Backend: dead, Timeout: time.Second})
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeFrame(conn, query(42, "example.com", 0)); err != nil {
		t.Fatal(err)
	}
	resp, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(resp) != 42 || resp[3]&0x0F != 2 {
		t.Fatalf("want SERVFAIL for ID 42, got % x", resp[:12])
	}
}

func TestTLSServer_ClosesIdleAndSurplusConnections(t *testing.T) {
	addr, conf := startDoT(t, &TLSServer{Backend: fakeResolver(t), Idle: 300 * time.Millisecond, MaxConns: 1})

	first, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	// With the one slot taken, the next connection is closed without an answer.
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("surplus connection: read returned %v, want EOF", err)
	}

	// And the first, never asking anything, is dropped once idle.
	start := time.Now()
	_ = first.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection was not closed")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("idle connection closed after %s, want about 300ms", waited)
	}
}
