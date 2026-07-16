package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// fakeDeviceLookup returns a fixed endpoint pointing at the test target.
type fakeDeviceLookup struct{ ep access.Endpoint }

func (f fakeDeviceLookup) Endpoint(context.Context, access.Scope, uuid.UUID) (access.Endpoint, error) {
	return f.ep, nil
}

// fakeResolver returns a fixed credential, or a fixed error (e.g. ErrNoCredential).
type fakeResolver struct {
	cred access.Credential
	err  error
}

func (f fakeResolver) Resolve(context.Context, *access.Session) (access.Credential, error) {
	return f.cred, f.err
}

func (f fakeResolver) HasCredential(context.Context, access.Scope, uuid.UUID) (bool, error) {
	return f.err == nil, f.err
}

func TestGateway_InjectsBasicAuthServerSide(t *testing.T) {
	// Target device requires Basic auth and echoes whether it was authenticated.
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "s3cret-pw" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("auth required"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("device-admin-ok"))
	}))
	defer target.Close()

	gw := NewHTTPGateway(
		fakeDeviceLookup{ep: access.Endpoint{
			Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true,
		}},
		nil, nil, "test-node",
	)

	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New()}
	live, err := gw.Establish(context.Background(), sess,
		fakeResolver{cred: access.Credential{Username: "admin", Secret: "s3cret-pw", Injection: "basic"}})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}

	// The client makes a request carrying NO credentials — only the session
	// token. The gateway injects the device credential on the way out.
	req := httptest.NewRequest(http.MethodGet, "/proxy/"+sess.ID.String()+"/dashboard", nil)
	if req.Header.Get("Authorization") != "" {
		t.Fatal("precondition: client request must carry no Authorization")
	}
	w := httptest.NewRecorder()
	if ok := gw.Serve(w, req, sess.ID, live.ProxyToken, "/dashboard"); !ok {
		t.Fatal("Serve returned false for a live session")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("proxied status = %d, want 200 (creds should have been injected)", w.Code)
	}
	if w.Body.String() != "device-admin-ok" {
		t.Fatalf("body = %q, want device-admin-ok", w.Body.String())
	}
	// The target saw injected Basic auth...
	if gotAuth == "" {
		t.Fatal("target did not receive injected Authorization header")
	}
	// ...but the credential value is never handed back to the client.
	if w.Header().Get("Authorization") != "" {
		t.Fatal("client response must not carry the device credential")
	}
}

func TestGateway_FailsClosedWithoutCredential(t *testing.T) {
	// A device with no bound credential and no break-glass opt-in must NOT get a
	// session — the gateway must not proxy it to the device's own login page.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	gw := NewHTTPGateway(fakeDeviceLookup{ep: access.Endpoint{
		Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true,
		AllowUnmanaged: false,
	}}, nil, nil, "n")
	sess := &access.Session{ID: uuid.New()}
	_, err := gw.Establish(context.Background(), sess, fakeResolver{err: access.ErrNoCredential})
	if err == nil {
		t.Fatal("Establish must fail closed when no credential is bound")
	}
}

func TestGateway_BreakGlassAllowsUnmanaged(t *testing.T) {
	// A device that explicitly opts into break-glass gets a session with no
	// server-side injection (its own login page is proxied).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("no credential should be injected for an unmanaged device")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("device-login-page"))
	}))
	defer target.Close()
	gw := NewHTTPGateway(fakeDeviceLookup{ep: access.Endpoint{
		Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true,
		AllowUnmanaged: true,
	}}, nil, nil, "n")
	sess := &access.Session{ID: uuid.New()}
	live, err := gw.Establish(context.Background(), sess, fakeResolver{err: access.ErrNoCredential})
	if err != nil {
		t.Fatalf("break-glass establish should succeed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	if ok := gw.Serve(w, req, sess.ID, live.ProxyToken, "/"); !ok {
		t.Fatal("Serve returned false for a live break-glass session")
	}
	if w.Body.String() != "device-login-page" {
		t.Fatalf("body = %q, want device-login-page", w.Body.String())
	}
}

func TestGateway_RejectsWrongToken(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	gw := NewHTTPGateway(fakeDeviceLookup{ep: access.Endpoint{Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true}}, nil, nil, "n")
	sess := &access.Session{ID: uuid.New()}
	if _, err := gw.Establish(context.Background(), sess, fakeResolver{}); err != nil {
		t.Fatalf("establish: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if gw.Serve(httptest.NewRecorder(), req, sess.ID, "wrong-token", "/") {
		t.Fatal("Serve must reject a wrong session token")
	}
}

func TestGateway_RejectsAfterEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()
	gw := NewHTTPGateway(fakeDeviceLookup{ep: access.Endpoint{Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true}}, nil, nil, "n")
	sess := &access.Session{ID: uuid.New()}
	live, _ := gw.Establish(context.Background(), sess, fakeResolver{})
	_ = gw.End(context.Background(), sess.ID)
	if gw.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), sess.ID, live.ProxyToken, "/") {
		t.Fatal("Serve must reject after the session is ended")
	}
}
