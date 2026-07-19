package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// respFor builds a text/html response as if answering a request with the given
// Sec-Fetch-Dest.
func respFor(dest, body string) *http.Response {
	req := &http.Request{Header: http.Header{}}
	if dest != "" {
		req.Header.Set("Sec-Fetch-Dest", dest)
	}
	r := &http.Response{
		Header:  http.Header{},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}
	r.Header.Set("Content-Type", "text/html")
	return r
}

// The exact byte a FortiGate returns from its login POST.
//
// It is one character, "0", under Content-Type: text/html — a status code, not a
// page. login.js reads retval.charAt(0) to branch and eval()s the rest. Injecting
// <base> and the shim ahead of it turned that first character into "<", which
// matches no status, so a CORRECT password silently read as rejected. The
// response must survive byte-for-byte.
func TestXHRResponseIsNotRewritten(t *testing.T) {
	resp := respFor("empty", "0")
	if err := modifyResponse(testPrefix)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if body != "0" {
		t.Errorf("XHR response = %q (%d bytes), want %q untouched; "+
			"injecting into it makes charAt(0) '<' and the login fails with correct credentials",
			body, len(body), "0")
	}
}

// A success payload is status char + JavaScript that gets eval'd. Injection would
// corrupt both the status and the script.
func TestXHRScriptPayloadSurvivesIntact(t *testing.T) {
	const payload = `0document.location="/ng/prompt?viewOnly&redir=%2F";`
	resp := respFor("empty", payload)
	if err := modifyResponse(testPrefix)(resp); err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); body != payload {
		t.Errorf("eval payload was rewritten:\n got: %s\nwant: %s", body, payload)
	}
}

// The frame the operator actually looks at still gets <base>, the shim and the
// watermark — the fix must not disarm the controls on real pages.
func TestDocumentAndIframeAreStillRewritten(t *testing.T) {
	for _, dest := range []string{"document", "iframe", "frame"} {
		resp := respFor(dest, `<html><head></head><body>hi</body></html>`)
		if err := modifyResponse(testPrefix)(resp); err != nil {
			t.Fatal(err)
		}
		body := readBody(t, resp)
		if !strings.Contains(body, `<base href="`+testPrefix+`">`) {
			t.Errorf("Sec-Fetch-Dest=%s: base not injected; the device UI would escape the session", dest)
		}
		if !strings.Contains(body, "window.fetch=function") {
			t.Errorf("Sec-Fetch-Dest=%s: shim not injected", dest)
		}
	}
}

// Sub-resources are data too: a script or stylesheet served as text/html must not
// have markup spliced into it.
func TestSubresourceDestsAreNotRewritten(t *testing.T) {
	for _, dest := range []string{"script", "style", "image", "font"} {
		resp := respFor(dest, "0")
		if err := modifyResponse(testPrefix)(resp); err != nil {
			t.Fatal(err)
		}
		if body := readBody(t, resp); body != "0" {
			t.Errorf("Sec-Fetch-Dest=%s was rewritten to %q", dest, body)
		}
	}
}

// With no Sec-Fetch-Dest (a non-browser client, or one too old to send it),
// behaviour is unchanged: nothing is rendering it, so injection cannot break a
// page, and existing callers keep working.
func TestAbsentSecFetchDestFallsBackToRewriting(t *testing.T) {
	resp := respFor("", `<html><head></head><body>hi</body></html>`)
	if err := modifyResponse(testPrefix)(resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readBody(t, resp), `<base href="`+testPrefix+`">`) {
		t.Error("a request without Sec-Fetch-Dest should still be rewritten")
	}
}

// A brokered device must not install a service worker in the operator's browser.
//
// The worker runs in its own context where the shim does not exist, so every
// root-absolute URL it fetches escapes the session; and it outlives the session,
// caching one device's responses in the operator's browser. A FortiGate registers
// "/service-worker.js" at root scope, which escaped to GuardRail and then died on
// the containment redirect anyway — the spec forbids registering a redirected
// script.
func TestShimRefusesServiceWorkerRegistration(t *testing.T) {
	resp := respFor("iframe", `<html><head></head><body></body></html>`)
	if err := modifyResponse(testPrefix)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "navigator.serviceWorker.register=function()") {
		t.Errorf("service worker registration is not neutralised; the worker escapes the session prefix: %s", body)
	}
	// It must reject rather than pretend to succeed: a fake registration object
	// would be used by the caller and fail in a stranger way.
	if !strings.Contains(body, "Promise.reject") {
		t.Errorf("registration should reject (as browsers do on http:// and in private mode), not resolve: %s", body)
	}
}

// pushState/replaceState change the URL with no network request, so an escape
// here is silent: nothing fails, nothing logs, the address is just no longer
// under the session prefix — and a router that keys off the document path stops
// matching its own routes and renders an empty page.
func TestShimPatchesHistoryNavigation(t *testing.T) {
	resp := respFor("iframe", `<html><head></head><body></body></html>`)
	if err := modifyResponse(testPrefix)(resp); err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	for _, want := range []string{"history.pushState=function", "history.replaceState=function"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s not patched; a root-absolute history navigation escapes the session silently", want)
		}
	}
	// A null URL must stay null: pushState(state, title) is legal and means "same
	// URL". Passing rw(undefined) would navigate to the string "undefined".
	if !strings.Contains(body, "u==null?hp(s,t)") {
		t.Errorf("pushState with no URL is not handled: %s", body)
	}
}
