package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockIdP is a minimal OIDC provider: discovery, JWKS, and a token endpoint that
// mints an RS256 ID token for a fixed subject.
type mockIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	aud    string
	nonce  string
}

func newMockIdP(t *testing.T, aud, nonce string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	m := &mockIdP{key: key, aud: aud, nonce: nonce}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 m.issuer,
			"authorization_endpoint": m.issuer + "/authorize",
			"token_endpoint":         m.issuer + "/token",
			"jwks_uri":               m.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": "test-key", "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := jwt.MapClaims{
			"iss": m.issuer, "sub": "idp-subject-123", "aud": m.aud,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"email": "alice@corp.example", "preferred_username": "alice", "name": "Alice Example",
			"nonce": m.nonce,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": signed, "access_token": "at"})
	})
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	return m
}

func (m *mockIdP) close() { m.server.Close() }

func TestOIDC_ExchangeVerifiesIDToken(t *testing.T) {
	const aud, nonce = "guardrail-client", "n-0S6_WzA2Mj"
	idp := newMockIdP(t, aud, nonce)
	defer idp.close()

	p := NewOIDCProvider(OIDCConfig{Issuer: idp.issuer, ClientID: aud, RedirectURL: "https://app/cb"})
	p.SetHTTPClient(idp.server.Client())

	ext, err := p.Exchange(context.Background(), "the-code", "verifier", nonce)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ext.Subject != "idp-subject-123" {
		t.Fatalf("subject = %q", ext.Subject)
	}
	if ext.Email != "alice@corp.example" || ext.Username != "alice" {
		t.Fatalf("identity mismatch: %+v", ext)
	}
	if ext.Provider != "oidc" {
		t.Fatalf("provider = %q", ext.Provider)
	}
}

func TestOIDC_RejectsNonceMismatch(t *testing.T) {
	const aud = "guardrail-client"
	idp := newMockIdP(t, aud, "server-nonce")
	defer idp.close()

	p := NewOIDCProvider(OIDCConfig{Issuer: idp.issuer, ClientID: aud, RedirectURL: "https://app/cb"})
	p.SetHTTPClient(idp.server.Client())

	if _, err := p.Exchange(context.Background(), "code", "verifier", "different-nonce"); err == nil {
		t.Fatal("expected nonce mismatch to fail verification")
	}
}

func TestOIDC_RejectsWrongAudience(t *testing.T) {
	idp := newMockIdP(t, "some-other-client", "n1")
	defer idp.close()

	// Provider expects a different client id than the token's aud.
	p := NewOIDCProvider(OIDCConfig{Issuer: idp.issuer, ClientID: "guardrail-client", RedirectURL: "https://app/cb"})
	p.SetHTTPClient(idp.server.Client())

	if _, err := p.Exchange(context.Background(), "code", "verifier", "n1"); err == nil {
		t.Fatal("expected audience mismatch to fail verification")
	}
}

func TestOIDC_AuthCodeURL(t *testing.T) {
	idp := newMockIdP(t, "cid", "n")
	defer idp.close()
	p := NewOIDCProvider(OIDCConfig{Issuer: idp.issuer, ClientID: "cid", RedirectURL: "https://app/cb"})
	p.SetHTTPClient(idp.server.Client())

	u := p.AuthCodeURL("state123", "nonce123", "challenge123")
	for _, want := range []string{"response_type=code", "client_id=cid", "code_challenge=challenge123", "code_challenge_method=S256", "state=state123"} {
		if !contains(u, want) {
			t.Fatalf("auth url %q missing %q", u, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
