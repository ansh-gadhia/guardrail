package dnsrelay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// query builds a real DNS query for name/A, optionally with an EDNS OPT record
// advertising udpSize.
func query(id uint16, name string, udpSize int) []byte {
	var b bytes.Buffer
	h := make([]byte, headerLen)
	binary.BigEndian.PutUint16(h[0:], id)
	h[2] = 0x01 // RD
	binary.BigEndian.PutUint16(h[4:], 1)
	if udpSize > 0 {
		binary.BigEndian.PutUint16(h[10:], 1)
	}
	b.Write(h)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b.WriteByte(byte(len(l)))
		b.WriteString(l)
	}
	b.Write([]byte{0, 0, 1, 0, 1}) // root, A, IN
	if udpSize > 0 {
		opt := []byte{0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0} // root, OPT, class=size, ttl, rdlen 0
		binary.BigEndian.PutUint16(opt[3:], uint16(udpSize))
		b.Write(opt)
	}
	return b.Bytes()
}

// answer turns q into a reply carrying one A record per TTL given, each with a
// compressed name pointing back at the question.
func answer(q []byte, ttls ...uint32) []byte {
	end := questionEnd(q)
	out := append([]byte(nil), q[:end]...)
	out[2] |= flagQR
	binary.BigEndian.PutUint16(out[6:], uint16(len(ttls)))
	binary.BigEndian.PutUint16(out[10:], 0)
	for _, ttl := range ttls {
		rr := []byte{0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 10, 0, 0, 1}
		binary.BigEndian.PutUint32(rr[6:], ttl)
		out = append(out, rr...)
	}
	return out
}

// fakeResolver is an ordinary DNS server on TCP that answers every query with
// one A record, TTL 300 and 60.
func fakeResolver(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				q, err := readFrame(c)
				if err != nil {
					return
				}
				_ = writeFrame(c, answer(q, 300, 60))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestServer_AnswersPostAndGetFromTheResolver(t *testing.T) {
	srv := httptest.NewServer((&Server{Backend: fakeResolver(t)}).Handler())
	defer srv.Close()
	q := query(0, "db1.tunnel.guardrail.lan", 0)

	// POST, the form browsers use.
	resp, err := http.Post(srv.URL+"/dns-query", MediaType, bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != MediaType {
		t.Fatalf("POST: %s %q", resp.Status, resp.Header.Get("Content-Type"))
	}
	if !bytes.Equal(body[:2], q[:2]) || body[2]&flagQR == 0 || binary.BigEndian.Uint16(body[6:]) != 2 {
		t.Fatalf("POST: not the resolver's answer to this query: % x", body[:12])
	}
	// The smaller TTL decides how long an HTTP cache may keep it.
	if cc := resp.Header.Get("Cache-Control"); cc != "max-age=60" {
		t.Errorf("Cache-Control = %q, want max-age=60", cc)
	}

	// GET, base64url without padding.
	resp, err = http.Get(srv.URL + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET: %s", resp.Status)
	}
}

func TestServer_RefusesWhatIsNotADNSQuery(t *testing.T) {
	srv := httptest.NewServer((&Server{Backend: fakeResolver(t)}).Handler())
	defer srv.Close()
	cases := map[string]func() (*http.Response, error){
		"wrong content type": func() (*http.Response, error) {
			return http.Post(srv.URL+"/dns-query", "text/plain", strings.NewReader("hello, world"))
		},
		"too short": func() (*http.Response, error) {
			return http.Post(srv.URL+"/dns-query", MediaType, strings.NewReader("abc"))
		},
		"no parameter":  func() (*http.Response, error) { return http.Get(srv.URL + "/dns-query") },
		"not base64url": func() (*http.Response, error) { return http.Get(srv.URL + "/dns-query?dns=%%%") },
	}
	for name, try := range cases {
		resp, err := try()
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("%s: %s, want a 4xx", name, resp.Status)
		}
	}
}

func TestServer_SaysSoWhenTheResolverIsDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	srv := httptest.NewServer((&Server{Backend: dead, Timeout: time.Second}).Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/dns-query", MediaType, bytes.NewReader(query(1, "example.com", 0)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%s, want 502", resp.Status)
	}
}

// A DoH upstream over real TLS, which fails over from a dead one.
func TestForwarder_RelaysToTheFirstUpstreamThatAnswers(t *testing.T) {
	var got []byte
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", MediaType)
		_, _ = w.Write(answer(got, 120))
	}))
	defer up.Close()
	broken := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer broken.Close()

	f := &Forwarder{Upstreams: []string{broken.URL + "/dns-query", up.URL + "/dns-query"}, Client: up.Client()}
	q := query(7, "example.com", 0)
	resp := f.Exchange(context.Background(), q)
	if !bytes.Equal(got, q) {
		t.Fatal("the upstream did not receive the query unchanged")
	}
	if binary.BigEndian.Uint16(resp) != 7 || binary.BigEndian.Uint16(resp[6:]) != 1 {
		t.Fatalf("not the upstream's answer: % x", resp[:12])
	}

	// Nothing answers: a SERVFAIL for this query, at once.
	f.Upstreams = []string{broken.URL + "/dns-query"}
	resp = f.Exchange(context.Background(), q)
	if binary.BigEndian.Uint16(resp) != 7 || resp[3]&0x0F != 2 || resp[2]&flagQR == 0 {
		t.Fatalf("want SERVFAIL for id 7, got % x", resp[:12])
	}
}

// Over UDP, an answer bigger than the client can take comes back truncated,
// so it asks again over TCP — which then gets the whole answer.
func TestForwarder_UDPTruncatesAndTCPDoesNot(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		ttls := make([]uint32, 60) // 60 records: ~1000 bytes, over 512
		for i := range ttls {
			ttls[i] = 30
		}
		w.Header().Set("Content-Type", MediaType)
		_, _ = w.Write(answer(q, ttls...))
	}))
	defer up.Close()
	f := &Forwarder{Upstreams: []string{up.URL}, Client: up.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	go func() { _ = f.ServeUDP(ctx, pc) }()
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(query(9, "big.example", 0))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[2]&flagTC == 0 || n > 512 {
		t.Fatalf("UDP answer of %d bytes, TC=%v; want truncated", n, buf[2]&flagTC != 0)
	}

	// With EDNS advertising 4096 bytes it fits, and is not truncated.
	_, _ = c.Write(query(10, "big.example", 4096))
	n, _ = c.Read(buf)
	if buf[2]&flagTC != 0 || binary.BigEndian.Uint16(buf[6:n]) != 60 {
		t.Fatalf("EDNS 4096: TC=%v, %d answers", buf[2]&flagTC != 0, binary.BigEndian.Uint16(buf[6:]))
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = f.ServeTCP(ctx, ln) }()
	tc, _ := net.Dial("tcp", ln.Addr().String())
	defer func() { _ = tc.Close() }()
	_ = writeFrame(tc, query(11, "big.example", 0))
	resp, err := readFrame(tc)
	if err != nil {
		t.Fatal(err)
	}
	if resp[2]&flagTC != 0 || binary.BigEndian.Uint16(resp[6:]) != 60 {
		t.Fatalf("TCP: TC=%v, %d answers; want the whole answer", resp[2]&flagTC != 0, binary.BigEndian.Uint16(resp[6:]))
	}
}

func TestWireHelpers_SurviveGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 2, 3}, bytes.Repeat([]byte{0xFF}, 40), append(make([]byte, 12), 0x3F)} {
		_ = ServFail(b)
		_ = Truncated(b)
		_ = UDPSize(b)
		_, _ = MinTTL(b)
	}
}
