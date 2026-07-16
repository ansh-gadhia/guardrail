package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testPrefix    = "/proxy/abc123/"
	testWatermark = "alice@example.com · 1a2b3c4d"
)

func htmlResp(body string) *http.Response {
	r := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	r.Header.Set("Content-Type", "text/html; charset=utf-8")
	return r
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// The exact shape that broke a real FortiGate: an Angular index.html whose
// scripts and stylesheet are root-absolute.
//
// <base> does not touch these — a root-absolute URL resolves against the origin —
// so before rebasing, the browser asked GuardRail for /static/main.js, got the
// console's own index.html back as 200 text/html + nosniff, refused to execute
// it, and rendered a blank frame. Everything the operator could see (a 200, a
// page, no error in the log) said it had worked.
func TestRewriteHTMLRebasesRootAbsoluteAssets(t *testing.T) {
	resp := htmlResp(`<!DOCTYPE html><html lang="en"><head>` +
		`<link rel="stylesheet" href="/static/styles.css">` +
		`<link rel="icon" href="favicon/favicon.ico">` +
		`</head><body><app-root></app-root>` +
		`<script src="/static/runtime.js"></script>` +
		`<script src="/static/main.js"></script>` +
		`</body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	for _, want := range []string{
		`href="` + testPrefix + `static/styles.css"`,
		`src="` + testPrefix + `static/runtime.js"`,
		`src="` + testPrefix + `static/main.js"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("asset not rebased, want %s in: %s", want, body)
		}
	}
	// A document-relative URL must be left for <base> to resolve. Rebasing it too
	// would produce /proxy/<sid>/favicon/... only by luck — it is relative to the
	// document, not the root, and those differ on any nested page.
	if !strings.Contains(body, `href="favicon/favicon.ico"`) {
		t.Errorf("document-relative URL was rewritten; <base> should own it: %s", body)
	}
	// Our own injected base must not be double-prefixed.
	if !strings.Contains(body, `<base href="`+testPrefix+`">`) {
		t.Errorf("injected base was mangled: %s", body)
	}
}

// URLs that are not root-absolute paths must survive untouched. Rewriting any of
// these would break the page in a way that looks like the proxy corrupting the
// device UI.
func TestRewriteHTMLLeavesNonRootAbsoluteURLsAlone(t *testing.T) {
	resp := htmlResp(`<html><head></head><body>` +
		`<a href="#anchor">a</a>` +
		`<a href="?q=1">b</a>` +
		`<a href="https://example.com/x">c</a>` +
		`<a href="//cdn.example.com/y">d</a>` +
		`<a href="javascript:void(0)">e</a>` +
		`<img src="data:image/png;base64,AAAA">` +
		`<img srcset="/a.png 1x, /b.png 2x">` +
		`</body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	for _, want := range []string{
		`href="#anchor"`,
		`href="?q=1"`,
		`href="https://example.com/x"`,
		`href="//cdn.example.com/y"`,
		`href="javascript:void(0)"`,
		`src="data:image/png;base64,AAAA"`,
		`srcset="/a.png 1x, /b.png 2x"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("URL was rewritten but must not be, want %s in: %s", want, body)
		}
	}
}

// A form posting to the device's own API must stay in the session, or the login
// POST lands on GuardRail's API instead of the device's.
func TestRewriteHTMLRebasesFormAction(t *testing.T) {
	resp := htmlResp(`<html><head></head><body><form action="/api/v2/authenticate" method="post"></form></body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); !strings.Contains(body, `action="`+testPrefix+`api/v2/authenticate"`) {
		t.Errorf("form action not rebased: %s", body)
	}
}

// Rebasing must not double-prefix a URL that already points into the session,
// which happens on any page the device itself renders from a proxied response.
func TestRewriteHTMLDoesNotDoublePrefix(t *testing.T) {
	resp := htmlResp(`<html><head></head><body><script src="` + testPrefix + `static/main.js"></script></body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if strings.Contains(body, testPrefix+strings.TrimPrefix(testPrefix, "/")) {
		t.Errorf("URL was prefixed twice: %s", body)
	}
	if !strings.Contains(body, `src="`+testPrefix+`static/main.js"`) {
		t.Errorf("already-prefixed URL was mangled: %s", body)
	}
}

func TestRewriteHTMLInjectsBaseAndShim(t *testing.T) {
	resp := htmlResp(`<!doctype html><html><head><base href="/"><title>x</title></head><body>hi</body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if strings.Count(body, "<base") != 1 {
		t.Fatalf("expected exactly one <base>, got: %s", body)
	}
	if !strings.Contains(body, `<base href="`+testPrefix+`">`) {
		t.Errorf("base not rebased to prefix: %s", body)
	}
	if !strings.Contains(body, "window.fetch=function") {
		t.Errorf("fetch shim not injected: %s", body)
	}
	if got := resp.Header.Get("Content-Length"); got != itoa(len(body)) {
		t.Errorf("content-length %q != body len %d", got, len(body))
	}
}

func TestRewriteHTMLNoHeadFallsBackToPrepend(t *testing.T) {
	resp := htmlResp(`<div>no head here</div>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if !strings.HasPrefix(body, `<base href="`+testPrefix+`">`) {
		t.Errorf("expected base prepended, got: %s", body)
	}
}

func TestNonHTMLUntouched(t *testing.T) {
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"a":1}`))}
	resp.Header.Set("Content-Type", "application/json")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if b := readBody(t, resp); b != `{"a":1}` {
		t.Errorf("json body altered: %s", b)
	}
}

func TestRebaseLocationHeader(t *testing.T) {
	cases := map[string]string{
		"/ng/login":            testPrefix + "ng/login",
		"/":                    strings.TrimSuffix(testPrefix, "/") + "/",
		"https://host/x":       "https://host/x", // absolute → untouched
		"//cdn/x":              "//cdn/x",        // protocol-relative → untouched
		testPrefix + "already": testPrefix + "already",
	}
	for in, want := range cases {
		resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
		resp.Header.Set("Location", in)
		if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
			t.Fatal(err)
		}
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("Location %q -> %q, want %q", in, got, want)
		}
	}
}

func TestRebaseCookiePath(t *testing.T) {
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	resp.Header.Add("Set-Cookie", "sid=abc; Path=/; HttpOnly")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	got := resp.Header.Get("Set-Cookie")
	if !strings.Contains(got, "Path=/proxy/abc123/") {
		t.Errorf("cookie path not rebased: %s", got)
	}
	if !strings.Contains(got, "HttpOnly") {
		t.Errorf("cookie attrs lost: %s", got)
	}
}

func TestShimEscapesPrefix(t *testing.T) {
	// The prefix is server-built, but the shim must still be a safe JS literal:
	// a "</script>" inside the prefix must be neutralized so it can't close the
	// injected <script> early. The shim's own trailing </script> is legitimate.
	s := shim("/proxy/x/</script>/")
	if strings.Count(s, "</script>") != 1 {
		t.Errorf("prefix </script> not neutralized (want exactly the trailing one): %s", s)
	}
	if !strings.Contains(s, `\x3c/script>`) {
		t.Errorf("prefix < was not escaped to \\x3c: %s", s)
	}
}

// The watermark has to reach the document the user's browser renders, on both
// injection paths — including the no-<head> fallback, which is exactly the kind
// of odd document where a missed injection would go unnoticed.
func TestRewriteHTMLInjectsWatermark(t *testing.T) {
	for name, doc := range map[string]string{
		"with head":    `<!doctype html><html><head><title>x</title></head><body>hi</body></html>`,
		"without head": `<html><body>hi</body></html>`,
		"bare":         `hi`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := htmlResp(doc)
			if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
				t.Fatal(err)
			}
			body := readBody(t, resp)
			if !strings.Contains(body, testWatermark) {
				t.Errorf("watermark text absent from proxied document: %s", body)
			}
			if !strings.Contains(body, "pointer-events:none") {
				t.Errorf("watermark overlay not injected: %s", body)
			}
			if got := resp.Header.Get("Content-Length"); got != itoa(len(body)) {
				t.Errorf("content-length %q != body len %d", got, len(body))
			}
		})
	}
}

// Non-HTML responses (assets, XHR payloads) must be passed through untouched —
// injecting a script into a JSON API response would corrupt it.
func TestRewriteLeavesNonHTMLAlone(t *testing.T) {
	resp := htmlResp(`{"ok":true}`)
	resp.Header.Set("Content-Type", "application/json")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); body != `{"ok":true}` {
		t.Errorf("JSON body was rewritten: %s", body)
	}
}

// noCTResp models what a real embedded device sends: a body, and no
// Content-Type header at all.
func noCTResp(body string) *http.Response {
	r := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	return r
}

// The bug this pins: micro_httpd on the project's own test router sends no
// Content-Type, so isHTML("") was false and base+shim+watermark were silently
// skipped. net/http then sniffed the body on write, so the browser still got
// text/html and rendered fine — the injection was simply absent, with nothing
// to show for it.
func TestRewriteInjectsWhenDeviceOmitsContentType(t *testing.T) {
	// Byte-for-byte the shape the test router actually returns: no Content-Type,
	// no <head>, script straight inside <html>.
	resp := noCTResp("<html>\n<script language=\"javascript\">\nvar loginstatus='0';\n</script>\n<body>hi</body></html>")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, `<base href="`+testPrefix+`">`) {
		t.Errorf("no <base> injected into a Content-Type-less document:\n%s", body)
	}
	if !strings.Contains(body, "window.fetch=function") {
		t.Errorf("no URL shim injected:\n%s", body)
	}
	if !strings.Contains(body, testWatermark) {
		t.Errorf("no watermark injected:\n%s", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type must be declared once we rewrite, got %q", ct)
	}
	if got := resp.Header.Get("Content-Length"); got != itoa(len(body)) {
		t.Errorf("content-length %q != body len %d", got, len(body))
	}
}

// With no <head>, the injection must still land ahead of the device's first
// script: that script's relative URLs resolve against our <base>.
func TestInjectionPrecedesDeviceScriptWhenNoHead(t *testing.T) {
	resp := noCTResp("<html>\n<script>var a=1;</script>\n<body>hi</body></html>")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	base := strings.Index(body, "<base")
	script := strings.Index(body, "var a=1")
	if base < 0 || script < 0 {
		t.Fatalf("missing markers in:\n%s", body)
	}
	if base > script {
		t.Errorf("<base> must precede the device's first script:\n%s", body)
	}
}

// A device that omits Content-Type on a NON-HTML asset must not be rewritten —
// sniffing has to actually decide, not wave everything through.
func TestNoContentTypeNonHTMLLeftAlone(t *testing.T) {
	png := string([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13})
	resp := noCTResp(png)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); body != png {
		t.Errorf("a sniffed-PNG body was rewritten (%d bytes)", len(body))
	}
}

// A declared non-HTML type must short-circuit before the body is buffered.
func TestDeclaredNonHTMLNotBuffered(t *testing.T) {
	resp := htmlResp(`body{color:red}`)
	resp.Header.Set("Content-Type", "text/css;charset=utf-8")
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); body != `body{color:red}` {
		t.Errorf("css was rewritten: %s", body)
	}
}

// A FortiGate's /logout is exactly this, and nothing else. Inside the console's
// session frame, "top" is the operator's console tab: unrewritten, this single
// line navigates the whole console away and the session view is gone. No
// client-side shim can prevent it (window.top and Location are unforgeable), so
// it has to be caught server-side.
func TestRewriteHTMLContainsFrameBusting(t *testing.T) {
	resp := htmlResp(`<script language="javascript">` + "\n" + `top.location="/login";` + "\n" + `</script>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if strings.Contains(body, `top.location=`) {
		t.Errorf("top.location survived; the device UI can still navigate the operator's console away: %s", body)
	}
	if !strings.Contains(body, `window.location="/login"`) {
		t.Errorf("navigation was not retargeted at the frame: %s", body)
	}
}

// parent.location busts one frame instead of all of them; same problem.
func TestRewriteHTMLContainsParentNavigation(t *testing.T) {
	for _, in := range []string{
		`<script>parent.location = "/x";</script>`,
		`<script>top . location . href = "/y";</script>`,
		`<script>window.top.location.replace("/z");</script>`,
	} {
		resp := htmlResp(in)
		if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
			t.Fatal(err)
		}
		body := readBody(t, resp)
		// The <script> content is what matters; assert no top/parent navigation remains.
		if frameBustRe.MatchString(body) {
			t.Errorf("frame-busting survived in %q -> %s", in, body)
		}
	}
}

// The browser pre-scans only the first 1024 bytes for the encoding declaration.
// The shim and the watermark are kilobytes, so injecting ahead of <meta charset>
// pushed it out of that window and the encoding fell back to a guess — the device
// sends "text/html" with no charset, so nothing authoritative was left anywhere.
func TestRewriteHTMLKeepsCharsetInPrescanWindow(t *testing.T) {
	resp := htmlResp(`<!DOCTYPE html><html lang="en"><head>` +
		`<meta charset="utf-8">` +
		`<title>FortiGate</title>` +
		`</head><body><fos-root></fos-root></body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	idx := strings.Index(strings.ToLower(body), "<meta charset")
	if idx < 0 {
		t.Fatalf("charset meta lost entirely: %s", body)
	}
	if idx >= 1024 {
		t.Errorf("charset meta at byte %d, past the browser's 1024-byte prescan window; the encoding falls back to a guess", idx)
	}
	// And the base must still precede everything that resolves a URL.
	base := strings.Index(body, `<base href="`+testPrefix+`">`)
	if base < 0 {
		t.Fatal("base tag missing")
	}
	if title := strings.Index(body, "<title>"); title >= 0 && base > title {
		t.Error("base injected after <title>; it must lead the URL-resolving content")
	}
}

// The http-equiv spelling counts too.
func TestRewriteHTMLHandlesHTTPEquivCharset(t *testing.T) {
	resp := htmlResp(`<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>x</title></head><body>b</body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if idx := strings.Index(strings.ToLower(body), "<meta http-equiv"); idx < 0 || idx >= 1024 {
		t.Errorf("http-equiv charset at %d, want inside the 1024-byte window", idx)
	}
}

// A document with no charset declaration still gets the injection right after
// <head>, exactly as before.
func TestRewriteHTMLNoCharsetStillInjectsAtHead(t *testing.T) {
	resp := htmlResp(`<html><head><title>x</title></head><body>b</body></html>`)
	if err := modifyResponse(testPrefix, testWatermark)(resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readBody(t, resp), `<head><base href="`+testPrefix+`">`) {
		t.Error("expected injection immediately after <head> when no charset is declared")
	}
}
