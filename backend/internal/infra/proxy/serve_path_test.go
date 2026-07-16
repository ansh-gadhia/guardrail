package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// upstreamSpy records exactly what the device was asked for.
type upstreamSpy struct {
	gotPath  string
	gotQuery string
	gotURI   string
}

func newSpiedGateway(t *testing.T, spy *upstreamSpy) (*HTTPGateway, uuid.UUID, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy.gotPath = r.URL.Path
		spy.gotQuery = r.URL.RawQuery
		spy.gotURI = r.RequestURI
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	g := NewHTTPGateway(nil, nil, nil, "test")
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sid := uuid.New()
	token := "tok"
	prefix := "/proxy/" + sid.String() + "/"
	// Built the same way Establish builds it, so the test exercises the real
	// director and response rewriting rather than a stand-in.
	g.sessions[sid] = &sessionCtx{
		target: target,
		token:  token,
		proxy: &httputil.ReverseProxy{
			Director:       g.director(target, nil, access.Credential{Injection: "none"}, prefix),
			ModifyResponse: modifyResponse(prefix, "op@example.com"),
		},
		expiresAt: time.Now().Add(time.Hour),
	}
	return g, sid, token
}

// A request carrying a query must reach the device as a path AND a query.
//
// URL.Path is the DECODED path, so a '?' inside it is a literal character, not a
// delimiter — Go re-encodes it as %3F. The device then receives a path that does
// not exist, and an appliance SPA answers unknown paths with its shell. A
// FortiGate's shell immediately asks whether it is logged in, is told no, and
// navigates to /logout?redir=... — which lands here again and returns the shell
// again. An infinite loop, from a single character in the wrong field.
func TestServeSplitsQueryFromPath(t *testing.T) {
	spy := &upstreamSpy{}
	g, sid, token := newSpiedGateway(t, spy)

	req := httptest.NewRequest(http.MethodGet, "https://gr.local/proxy/"+sid.String()+"/logout?redir=%2F", nil)
	w := httptest.NewRecorder()

	if !g.Serve(w, req, sid, token, "/logout?redir=%2F") {
		t.Fatal("Serve returned false")
	}
	if spy.gotPath != "/logout" {
		t.Errorf("device saw path %q, want %q — a '?' in URL.Path is escaped to %%3F and the page is never found", spy.gotPath, "/logout")
	}
	if spy.gotQuery != "redir=%2F" {
		t.Errorf("device saw query %q, want %q", spy.gotQuery, "redir=%2F")
	}
	if got := spy.gotURI; got != "/logout?redir=%2F" {
		t.Errorf("device saw request-uri %q, want %q", got, "/logout?redir=%2F")
	}
}

// The no-query case must keep working exactly as before.
func TestServeWithoutQuery(t *testing.T) {
	spy := &upstreamSpy{}
	g, sid, token := newSpiedGateway(t, spy)

	req := httptest.NewRequest(http.MethodGet, "https://gr.local/proxy/"+sid.String()+"/static/styles.css", nil)
	if !g.Serve(httptest.NewRecorder(), req, sid, token, "/static/styles.css") {
		t.Fatal("Serve returned false")
	}
	if spy.gotPath != "/static/styles.css" {
		t.Errorf("device saw path %q, want /static/styles.css", spy.gotPath)
	}
	if spy.gotQuery != "" {
		t.Errorf("device saw query %q, want none", spy.gotQuery)
	}
}

// The device root, with a query, is the login redirect's shape.
func TestServeRootWithQuery(t *testing.T) {
	spy := &upstreamSpy{}
	g, sid, token := newSpiedGateway(t, spy)

	req := httptest.NewRequest(http.MethodGet, "https://gr.local/proxy/"+sid.String()+"/?a=1&b=2", nil)
	if !g.Serve(httptest.NewRecorder(), req, sid, token, "/?a=1&b=2") {
		t.Fatal("Serve returned false")
	}
	if spy.gotPath != "/" {
		t.Errorf("device saw path %q, want /", spy.gotPath)
	}
	if spy.gotQuery != "a=1&b=2" {
		t.Errorf("device saw query %q, want a=1&b=2", spy.gotQuery)
	}
}
