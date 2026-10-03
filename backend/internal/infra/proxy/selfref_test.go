package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSelfRefRewriter(t *testing.T) {
	path := newSelfRefRewriter(mustURL(t, "http://10.0.0.5:8090"), "/proxy/sid")
	tunnel := newSelfRefRewriter(mustURL(t, "http://10.0.0.5"), "https://sid.tunnel.corp")
	cases := []struct {
		name string
		r    *selfRefRewriter
		in   string
		want string
	}{
		{"an absolute link", path, `<a href="http://10.0.0.5:8090/status.htm">`, `<a href="/proxy/sid/status.htm">`},
		{"a bare origin", path, `action="http://10.0.0.5:8090"`, `action="/proxy/sid"`},
		{"protocol-relative", path, `src="//10.0.0.5:8090/app.js"`, `src="/proxy/sid/app.js"`},
		{"JSON-escaped", path, `{"next":"http:\/\/10.0.0.5:8090\/home"}`, `{"next":"\/proxy\/sid\/home"}`},
		{"case does not matter", path, `HTTP://10.0.0.5:8090/x`, `/proxy/sid/x`},
		{"another port is somewhere else", path, `http://10.0.0.5:8091/x`, `http://10.0.0.5:8091/x`},
		{"a longer address is somewhere else", path, `http://10.0.0.55:8090/x`, `http://10.0.0.55:8090/x`},
		{"the device's HTTPS service is left alone", path, `https://10.0.0.5:8090/x`, `https://10.0.0.5:8090/x`},
		{"default port, written or not", tunnel, `http://10.0.0.5/a http://10.0.0.5:80/b`, `https://sid.tunnel.corp/a https://sid.tunnel.corp/b`},
		{"default port: an explicit other port is somewhere else", tunnel, `http://10.0.0.5:8080/a`, `http://10.0.0.5:8080/a`},
		{"tunnel protocol-relative", tunnel, `url(//10.0.0.5/bg.png)`, `url(//sid.tunnel.corp/bg.png)`},
		{"nothing to do", path, `plain text, no address`, `plain text, no address`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.rewriteString(c.in); got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}

	v6 := newSelfRefRewriter(mustURL(t, "http://[fd00::5]:8080"), "/proxy/sid")
	if got := v6.rewriteString(`http://[fd00::5]:8080/x`); got != `/proxy/sid/x` {
		t.Errorf("IPv6: got %s", got)
	}
	var nilR *selfRefRewriter
	if got := nilR.rewriteString("http://x"); got != "http://x" {
		t.Errorf("nil rewriter changed input: %s", got)
	}
}

func textResponse(ct, body string) *http.Response {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)), Request: &http.Request{Header: http.Header{}}}
}

func TestSelfRefRewriter_BodiesAndHeaders(t *testing.T) {
	r := newSelfRefRewriter(mustURL(t, "http://10.0.0.5:8090"), "https://sid.tunnel.corp")
	csp := newSelfRefRewriter(mustURL(t, "http://10.0.0.5:8090"), "'self'")

	// A redirect and a CSP naming the device.
	h := http.Header{}
	h.Set("Location", "http://10.0.0.5:8090/login.htm")
	h.Set("Content-Security-Policy", "script-src http://10.0.0.5:8090 'unsafe-inline'")
	r.rewriteHeaders(h, csp)
	if h.Get("Location") != "https://sid.tunnel.corp/login.htm" {
		t.Errorf("Location = %s", h.Get("Location"))
	}
	if h.Get("Content-Security-Policy") != "script-src 'self' 'unsafe-inline'" {
		t.Errorf("CSP = %s", h.Get("Content-Security-Policy"))
	}

	body := func(resp *http.Response) string {
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	// Text is rewritten, with the length kept right.
	resp := textResponse("text/css", "a{background:url(http://10.0.0.5:8090/bg.png)}")
	if err := r.rewriteBody(resp); err != nil {
		t.Fatal(err)
	}
	if got := body(resp); got != "a{background:url(https://sid.tunnel.corp/bg.png)}" || resp.ContentLength != int64(len(got)) {
		t.Errorf("css: %q (length %d)", got, resp.ContentLength)
	}
	// Binary is not touched, even if the bytes happen to contain the address.
	img := "\x89PNG http://10.0.0.5:8090/"
	resp = textResponse("image/png", img)
	_ = r.rewriteBody(resp)
	if body(resp) != img {
		t.Error("an image was rewritten")
	}
	// A compressed body cannot be searched, so it is passed through.
	resp = textResponse("text/html", "\x1f\x8b...")
	resp.Header.Set("Content-Encoding", "gzip")
	_ = r.rewriteBody(resp)
	if body(resp) != "\x1f\x8b..." {
		t.Error("a gzip body was rewritten")
	}
	// An event stream never ends; it is not read.
	if rewritableText("text/event-stream") {
		t.Error("event streams must not be read to the end")
	}
	// Over the cap, the body streams through intact.
	big := strings.Repeat("x", maxSelfRefBody) + "http://10.0.0.5:8090/"
	resp = textResponse("text/plain", big)
	resp.ContentLength = -1
	_ = r.rewriteBody(resp)
	if got := body(resp); got != big {
		t.Errorf("an over-size body changed (len %d, want %d)", len(got), len(big))
	}
}

// Path mode end to end: the router-style redirect and page land inside the
// session prefix, and a data response keeps every byte but the address.
func TestModifyResponseFor_SelfReferences(t *testing.T) {
	target := mustURL(t, "http://10.0.0.5:8090")
	hook := modifyResponseFor("/proxy/sid/", newSelfRefRewriter(target, "/proxy/sid"), newSelfRefRewriter(target, "'self'"))

	redirect := textResponse("", "")
	redirect.StatusCode = http.StatusFound
	redirect.Header.Set("Location", "http://10.0.0.5:8090/login.htm")
	if err := hook(redirect); err != nil {
		t.Fatal(err)
	}
	if got := redirect.Header.Get("Location"); got != "/proxy/sid/login.htm" {
		t.Errorf("redirect escaped the session: %s", got)
	}

	page := textResponse("text/html", `<html><head></head><body><form action="http://10.0.0.5:8090/login.cgi"></form></body></html>`)
	page.Request.Header.Set("Sec-Fetch-Dest", "document")
	if err := hook(page); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(page.Body)
	if !bytes.Contains(b, []byte(`action="/proxy/sid/login.cgi"`)) || bytes.Contains(b, []byte("10.0.0.5")) {
		t.Errorf("page still names the device: %s", b)
	}

	data := textResponse("text/html", "0http://10.0.0.5:8090/next")
	data.Request.Header.Set("Sec-Fetch-Dest", "empty")
	if err := hook(data); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(data.Body); string(b) != "0/proxy/sid/next" {
		t.Errorf("data response: %q, want only the address changed", b)
	}
}
