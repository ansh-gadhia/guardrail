// Package doh relays DNS between DNS over HTTPS (RFC 8484) and ordinary DNS.
//
// Two directions, both plain byte relays — a DNS message goes through
// unchanged, so nothing here resolves anything or needs to understand more of
// the wire format than a few header fields:
//
//   - Server answers DoH clients (a browser, Windows' encrypted DNS) by handing
//     each query to an ordinary resolver over TCP — the bundled dnsmasq, which
//     holds the tunnel wildcard and the operator's own records.
//   - Forwarder is the other way round: it answers ordinary DNS on UDP and TCP
//     by sending each query to DoH upstreams, so that the resolver's own
//     lookups leave the host encrypted as well.
package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MediaType is the RFC 8484 content type for a DNS message.
	MediaType = "application/dns-message"
	// maxMessage is the largest DNS message there is: TCP frames it in 16 bits.
	maxMessage = 65535
	headerLen  = 12
)

// Server answers DNS-over-HTTPS requests from an ordinary DNS resolver.
type Server struct {
	// Backend is the resolver's host:port. Queries go to it over TCP, which has
	// no size limit to trip over and so never answers with a truncated reply.
	Backend string
	// Timeout bounds one query end to end. Zero means five seconds.
	Timeout time.Duration
}

// Handler serves /dns-query (RFC 8484, GET and POST) and /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.serveQuery)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return mux
}

func (s *Server) serveQuery(w http.ResponseWriter, r *http.Request) {
	var msg []byte
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		// base64url without padding, per the RFC; padding is tolerated.
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(q, "="))
		if err != nil {
			http.Error(w, "dns parameter is not base64url", http.StatusBadRequest)
			return
		}
		msg = b
	case http.MethodPost:
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != MediaType {
			http.Error(w, "content type must be "+MediaType, http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+1))
		if err != nil {
			http.Error(w, "could not read the query", http.StatusBadRequest)
			return
		}
		if len(b) > maxMessage {
			http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
			return
		}
		msg = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(msg) < headerLen || len(msg) > maxMessage {
		http.Error(w, "not a DNS message", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.timeout())
	defer cancel()
	resp, err := ExchangeTCP(ctx, s.Backend, msg)
	if err != nil {
		http.Error(w, "the resolver did not answer", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", MediaType)
	// RFC 8484 §5.1: freshness should follow the answer's smallest TTL, so an
	// HTTP cache never holds a record longer than DNS would.
	if ttl, ok := MinTTL(resp); ok {
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(ttl), 10))
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	_, _ = w.Write(resp)
}

func (s *Server) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 5 * time.Second
}

// ExchangeTCP sends one DNS message to addr over TCP and returns the reply.
func ExchangeTCP(ctx context.Context, addr string, msg []byte) ([]byte, error) {
	if len(msg) > maxMessage {
		return nil, errors.New("doh: message too large")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame, uint16(len(msg))) // #nosec G115 -- bounded by maxMessage above
	copy(frame[2:], msg)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	return readFrame(conn)
}

func readFrame(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(n[:]))
	if size < headerLen {
		return nil, fmt.Errorf("doh: short DNS message (%d bytes)", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > maxMessage {
		return errors.New("doh: message too large")
	}
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame, uint16(len(msg))) // #nosec G115 -- bounded above
	copy(frame[2:], msg)
	_, err := w.Write(frame)
	return err
}

// ---- Forwarder: ordinary DNS in, DNS over HTTPS out -------------------------

// Forwarder answers ordinary DNS by relaying each query to DoH upstreams.
type Forwarder struct {
	// Upstreams are RFC 8484 endpoints, tried in order: https://1.1.1.1/dns-query.
	Upstreams []string
	Client    *http.Client
	// Timeout bounds one query across every upstream. Zero means five seconds.
	Timeout time.Duration
}

// Exchange sends msg to the first upstream that answers. When none does, it
// returns a SERVFAIL for the query rather than nothing, so the client fails at
// once instead of waiting out its own timeout.
func (f *Forwarder) Exchange(ctx context.Context, msg []byte) []byte {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, u := range f.Upstreams {
		if resp, err := f.post(ctx, u, msg); err == nil {
			return resp
		}
	}
	return ServFail(msg)
}

func (f *Forwarder) post(ctx context.Context, url string, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", MediaType)
	req.Header.Set("Accept", MediaType)
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req) // #nosec G107 -- the URL is the operator's configured upstream
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s answered %s", url, resp.Status)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != MediaType {
		return nil, fmt.Errorf("doh: %s answered %q, not a DNS message", url, mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		return nil, err
	}
	if len(body) < headerLen || len(body) > maxMessage {
		return nil, fmt.Errorf("doh: %s answered %d bytes, not a DNS message", url, len(body))
	}
	return body, nil
}

// ServeUDP answers queries arriving on pc until ctx ends.
func (f *Forwarder) ServeUDP(ctx context.Context, pc net.PacketConn) error {
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, maxMessage)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n < headerLen {
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			resp := f.Exchange(ctx, query)
			// Too big for this client's UDP buffer: send the header with TC set,
			// and it asks again over TCP — the ordinary DNS answer to this.
			if len(resp) > UDPSize(query) {
				resp = Truncated(resp)
			}
			_, _ = pc.WriteTo(resp, from)
		}()
	}
}

// ServeTCP answers queries arriving on ln until ctx ends.
func (f *Forwarder) ServeTCP(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer func() { _ = conn.Close() }()
			for {
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				q, err := readFrame(conn)
				if err != nil {
					return
				}
				if err := writeFrame(conn, f.Exchange(ctx, q)); err != nil {
					return
				}
			}
		}()
	}
}

// ---- The little of the wire format this needs -------------------------------

// flags: QR is the top bit of byte 2, TC the second-lowest bit of byte 2, and
// RCODE the low four bits of byte 3.
const (
	flagQR = 0x80
	flagTC = 0x02
	flagRA = 0x80
)

// ServFail builds a SERVFAIL reply to query, echoing its ID and question.
func ServFail(query []byte) []byte {
	if len(query) < headerLen {
		return nil
	}
	end := questionEnd(query)
	out := append([]byte(nil), query[:end]...)
	out[2] = (query[2] | flagQR) &^ flagTC
	out[3] = flagRA | 2 // RA, RCODE=SERVFAIL
	if end == headerLen {
		binary.BigEndian.PutUint16(out[4:], 0)
	}
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}

// Truncated cuts resp to its header and question, with TC set.
func Truncated(resp []byte) []byte {
	if len(resp) < headerLen {
		return resp
	}
	end := questionEnd(resp)
	out := append([]byte(nil), resp[:end]...)
	out[2] |= flagTC
	if end == headerLen {
		binary.BigEndian.PutUint16(out[4:], 0)
	}
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}

// UDPSize is the largest reply the querier can take over UDP: 512 bytes, or
// what its EDNS OPT record advertises.
func UDPSize(query []byte) int {
	const plain = 512
	if len(query) < headerLen {
		return plain
	}
	off := questionEnd(query)
	if off == headerLen && binary.BigEndian.Uint16(query[4:]) > 0 {
		return plain // a question that does not parse
	}
	for _, sec := range []int{6, 8, 10} {
		count := int(binary.BigEndian.Uint16(query[sec:]))
		for i := 0; i < count; i++ {
			var ok bool
			if off, ok = skipName(query, off); !ok || off+10 > len(query) {
				return plain
			}
			typ := binary.BigEndian.Uint16(query[off:])
			class := int(binary.BigEndian.Uint16(query[off+2:]))
			rdlen := int(binary.BigEndian.Uint16(query[off+8:]))
			if sec == 10 && typ == 41 { // OPT: the class field is the UDP size
				if class > plain {
					return class
				}
				return plain
			}
			off += 10 + rdlen
		}
	}
	return plain
}

// MinTTL is the smallest TTL among resp's answer records.
func MinTTL(resp []byte) (uint32, bool) {
	if len(resp) < headerLen {
		return 0, false
	}
	an := int(binary.BigEndian.Uint16(resp[6:]))
	if an == 0 {
		return 0, false
	}
	off := questionEnd(resp)
	if off == headerLen && binary.BigEndian.Uint16(resp[4:]) > 0 {
		return 0, false
	}
	var least uint32
	found := false
	for i := 0; i < an; i++ {
		var ok bool
		if off, ok = skipName(resp, off); !ok || off+10 > len(resp) {
			return least, found
		}
		ttl := binary.BigEndian.Uint32(resp[off+4:])
		if !found || ttl < least {
			least, found = ttl, true
		}
		off += 10 + int(binary.BigEndian.Uint16(resp[off+8:]))
	}
	return least, found
}

// questionEnd is the offset just past the question section, or the header's
// end when the question does not parse.
func questionEnd(msg []byte) int {
	off := headerLen
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	for i := 0; i < qd; i++ {
		var ok bool
		if off, ok = skipName(msg, off); !ok || off+4 > len(msg) {
			return headerLen
		}
		off += 4
	}
	return off
}

// skipName steps over a domain name at off, following no pointers: a pointer
// ends a name, so stepping over it is two bytes.
func skipName(msg []byte, off int) (int, bool) {
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case l&0xC0 != 0:
			return 0, false
		default:
			off += 1 + l
		}
	}
	return 0, false
}
