package proxy

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
)

const probeSecret = "hunter2-device-password"

func TestAuthHeaderBasicMatchesSetBasicAuth(t *testing.T) {
	// The derived value must be byte-identical to what net/http would have
	// produced, or this is a behaviour change to every proxied device rather
	// than a memory-handling change.
	cred := access.Credential{Injection: "basic", Username: "admin", Secret: probeSecret}

	got := httptest.NewRequest(http.MethodGet, "http://d/", nil)
	newAuthHeader(cred).apply(got)

	want := httptest.NewRequest(http.MethodGet, "http://d/", nil)
	want.SetBasicAuth(cred.Username, cred.Secret)

	if got.Header.Get("Authorization") != want.Header.Get("Authorization") {
		t.Fatalf("derived header differs from SetBasicAuth:\n got %q\nwant %q",
			got.Header.Get("Authorization"), want.Header.Get("Authorization"))
	}
	// And it really is the credential, not something that merely looks like one.
	enc := strings.TrimPrefix(got.Header.Get("Authorization"), "Basic ")
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || string(raw) != "admin:"+probeSecret {
		t.Fatalf("header does not decode to the credential: %q (%v)", raw, err)
	}
}

func TestAuthHeaderPassesRawHeaderValue(t *testing.T) {
	cred := access.Credential{Injection: "header", Secret: "Bearer abc123"}
	req := httptest.NewRequest(http.MethodGet, "http://d/", nil)
	newAuthHeader(cred).apply(req)
	if req.Header.Get("Authorization") != "Bearer abc123" {
		t.Fatalf("header injection = %q", req.Header.Get("Authorization"))
	}
}

// A credential that injects nothing must not be held at all.
func TestAuthHeaderInjectsNothingForNone(t *testing.T) {
	for _, inj := range []string{"none", "", "form", "ssh-password"} {
		a := newAuthHeader(access.Credential{Injection: inj, Secret: probeSecret})
		if a != nil {
			t.Errorf("injection %q produced a held header", inj)
			continue
		}
		// Deliberately calling through a nil receiver: apply and destroy are
		// written to be safe on one so no call site has to nil-check, and that
		// is the property under test here.
		var nilHeader *authHeader
		req := httptest.NewRequest(http.MethodGet, "http://d/", nil)
		nilHeader.apply(req)
		nilHeader.destroy()
		if req.Header.Get("Authorization") != "" {
			t.Errorf("injection %q set an Authorization header", inj)
		}
	}
}

// The point of the whole exercise: teardown must ERASE the bytes, not drop a
// reference and hope. A Go string cannot be overwritten, which is why the value
// is held as a []byte at all.
func TestAuthHeaderDestroyZeroesTheBytes(t *testing.T) {
	a := newAuthHeader(access.Credential{Injection: "header", Secret: probeSecret})
	if a == nil {
		t.Fatal("no header was built")
		return // unreachable; states for the reader and the linter that a is non-nil below
	}
	// Keep our own view of the same backing array, so we can see what teardown
	// did to the memory rather than to the pointer.
	backing := a.v
	if !bytes.Contains(backing, []byte(probeSecret)) {
		t.Fatal("the secret is not where the test thinks it is")
	}

	a.destroy()

	if bytes.Contains(backing, []byte(probeSecret)) {
		t.Fatal("destroy() left the secret readable in the backing array")
	}
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("byte %d is %d, want 0", i, b)
		}
	}
	if a.v != nil {
		t.Error("destroy() left the slice addressable")
	}
}

// A request that races teardown must inject nothing rather than read erased
// bytes — and must not panic.
func TestAuthHeaderAfterDestroyInjectsNothing(t *testing.T) {
	a := newAuthHeader(access.Credential{Injection: "header", Secret: probeSecret})
	a.destroy()
	req := httptest.NewRequest(http.MethodGet, "http://d/", nil)
	a.apply(req)
	if v := req.Header.Get("Authorization"); v != "" {
		t.Fatalf("a destroyed header still injected %q", v)
	}
	a.destroy() // idempotent
}

// apply runs on every proxied request while End may run concurrently.
func TestAuthHeaderIsRaceSafe(t *testing.T) {
	a := newAuthHeader(access.Credential{Injection: "header", Secret: probeSecret})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://d/", nil)
			a.apply(req)
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); a.destroy() }()
	wg.Wait()
}
