package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Device self-references: a device naming its own address.
//
// Embedded web UIs routinely write their own absolute origin into what they
// send: a login that redirects to "http://192.168.1.1/login.htm", a stylesheet
// at "http://192.168.1.1/style.css", a form whose action is the device's full
// URL. Re-served through GuardRail, each of those sends the browser straight to
// the device. From outside the device's network the page then never loads; from
// inside it, the browser talks to the device directly — no injected credential,
// no recording, no audit. Over the tunnel's HTTPS, an http:// script or
// stylesheet is mixed content, which the browser blocks, so a page that did load
// came up dead.
//
// So every reference the device makes to itself is re-pointed at GuardRail:
// the session prefix in path mode, the tunnel origin in tunnel mode. Only the
// device's own address is touched; everything else in a response is passed
// through byte for byte, which is what the data responses an appliance's
// scripts parse require (see rendersAsDocument).

// selfRefRewriter rewrites one device's references to itself.
type selfRefRewriter struct {
	subs []selfRefSub // longest first, so the most specific form wins
}

type selfRefSub struct {
	from []byte
	to   []byte
	// rel marks a protocol-relative form ("//host"). It must not be taken out
	// of the middle of a full URL with a different scheme: "https://host" is the
	// device's HTTPS service, not this origin, and cutting "//host" out of it
	// would leave "https:" dangling in front of GuardRail's address.
	rel bool
}

// newSelfRefRewriter builds the rewriter for target, replacing its origin with
// to: "/proxy/<sid>" in path mode, "https://<tunnel host>" in tunnel mode.
//
// The origin is matched as the device would write it: with its port, and
// without it when the port is the scheme's default; plain, protocol-relative,
// and with JSON's escaped slashes ("http:\/\/host"), which is how it appears in
// the configuration blobs appliance UIs load.
func newSelfRefRewriter(target *url.URL, to string) *selfRefRewriter {
	if target == nil || target.Host == "" {
		return nil
	}
	scheme := strings.ToLower(target.Scheme)
	host := strings.ToLower(target.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6
	}
	def := map[string]string{"http": "80", "https": "443"}[scheme]
	port := target.Port()
	if port == "" {
		port = def
	}
	auths := []string{host + ":" + port}
	if port == def {
		auths = append(auths, host)
	}
	// The protocol-relative replacement keeps the form it replaces: an absolute
	// destination loses its scheme ("//tunnel-host"), a path stays a path.
	toRel := to
	if i := strings.Index(to, "://"); i >= 0 {
		toRel = to[i+1:]
	}
	esc := func(s string) string { return strings.ReplaceAll(s, "/", `\/`) }

	r := &selfRefRewriter{}
	for _, a := range auths {
		r.subs = append(r.subs,
			selfRefSub{from: []byte(scheme + "://" + a), to: []byte(to)},
			selfRefSub{from: []byte(esc(scheme + "://" + a)), to: []byte(esc(to))},
			selfRefSub{from: []byte("//" + a), to: []byte(toRel), rel: true},
			selfRefSub{from: []byte(esc("//" + a)), to: []byte(esc(toRel)), rel: true},
		)
	}
	sort.SliceStable(r.subs, func(i, j int) bool { return len(r.subs[i].from) > len(r.subs[j].from) })
	return r
}

// rewrite returns b with every self-reference replaced, and whether any was.
func (r *selfRefRewriter) rewrite(b []byte) ([]byte, bool) {
	if r == nil || len(b) == 0 {
		return b, false
	}
	var out []byte
	changed := false
	last := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '/' && c != '\\' && c|0x20 != 'h' {
			continue
		}
		for _, s := range r.subs {
			end := i + len(s.from)
			if end > len(b) || !bytes.EqualFold(b[i:end], s.from) {
				continue
			}
			// A full URL starts wherever its scheme does — a FortiGate login
			// answers "0" with the next URL right behind it. Only the
			// protocol-relative form needs a clean start: "//host" inside
			// "https://host", or after a hostname character, is not it.
			if s.rel && i > 0 && (b[i-1] == ':' || isHostByte(b[i-1])) {
				continue
			}
			// A longer hostname ("host.example"), or a different port
			// ("host:8080" when this is "host"), is somewhere else.
			if end < len(b) && (isHostByte(b[end]) || b[end] == ':') {
				continue
			}
			if out == nil {
				out = make([]byte, 0, len(b)+64)
			}
			out = append(out, b[last:i]...)
			out = append(out, s.to...)
			last, changed = end, true
			i = end - 1
			break
		}
	}
	if !changed {
		return b, false
	}
	return append(out, b[last:]...), true
}

func (r *selfRefRewriter) rewriteString(s string) string {
	if out, ok := r.rewrite([]byte(s)); ok {
		return string(out)
	}
	return s
}

func isHostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
}

// rewriteHeaders re-points the headers that carry the device's address: where
// a redirect or refresh sends the browser, and the page's Content-Security-Policy,
// whose sources naming the device become 'self' — the page is now served from
// GuardRail, and a policy naming the device's address would block the page's own
// rewritten resources.
func (r *selfRefRewriter) rewriteHeaders(h http.Header, csp *selfRefRewriter) {
	if r == nil {
		return
	}
	for _, k := range []string{"Location", "Content-Location", "Refresh"} {
		if v := h.Get(k); v != "" {
			h.Set(k, r.rewriteString(v))
		}
	}
	if csp == nil {
		return
	}
	for _, k := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		vs := h.Values(k)
		for i, v := range vs {
			vs[i] = csp.rewriteString(v)
		}
	}
}

// maxSelfRefBody bounds the body read to rewrite self-references. Larger
// bodies — a firmware image, a log download — stream through untouched.
const maxSelfRefBody = 8 << 20

// rewriteBody replaces self-references in a text response body. Anything that
// is not text, is compressed, is a stream, or is too large passes through.
func (r *selfRefRewriter) rewriteBody(resp *http.Response) error {
	if r == nil || resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !rewritableText(ct) {
		return nil
	}
	if resp.ContentLength > maxSelfRefBody {
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, maxSelfRefBody+1))
	if err != nil {
		return err
	}
	if len(head) > maxSelfRefBody {
		// Too large after all: hand back what was read, then the rest, unchanged.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		return nil
	}
	_ = resp.Body.Close()
	if ct == "" && !rewritableText(http.DetectContentType(head)) {
		restoreBody(resp, head)
		return nil
	}
	out, _ := r.rewrite(head)
	restoreBody(resp, out)
	return nil
}

// rewritableText reports whether a content type is text a device could write
// its own address into. Event streams are excluded: they never end, and reading
// one to the end would hang it.
func rewritableText(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch {
	case mt == "text/event-stream":
		return false
	case strings.HasPrefix(mt, "text/"):
		return true
	case strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/javascript", "application/x-javascript", "application/ecmascript",
		"application/json", "application/xml", "application/xhtml+xml":
		return true
	}
	return false
}
