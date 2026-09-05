package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The SIEM signs RS256 from its JWKS and GuardRail holds no shared secret —
// that is the whole contract, and GUARDRAIL_SIEM_SSO_SECRET is meant to stay
// empty forever. This pins both halves of it: a JWKS-signed token verifies with
// no secret configured, and the symmetric path stays shut rather than falling
// back to something weaker.
//
// The empty secret is the interesting part. It looks like a missing setting, so
// the temptation is to "fix" it by asking the SIEM for one — which would hand
// this deployment a key that can FORGE their assertions instead of merely
// checking them. A test that fails the moment the asymmetric path stops working
// on its own is what makes that unnecessary.
func TestSSOWorksWithNoSharedSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "cs-sso-48fecc70"

	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64(key.N.Bytes()),
		"e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()

	// Pin the server's own certificate, exactly as siem-sso.sh does.
	caPath := filepath.Join(t.TempDir(), "jwks-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	}), 0o644); err != nil {
		t.Fatal(err)
	}

	src, err := NewJWKSSource(JWKSConfig{URL: srv.URL, CABundlePath: caPath, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("build JWKS source: %v", err)
	}

	// THE POINT: SharedSecret is empty, as it is on dc1.
	v := NewSSOVerifier(src, SSOVerifierConfig{
		Issuer: "cybersentinel-siem", Audience: "guardrail-pam", SharedSecret: "",
	})

	now := time.Now()
	claims := jwt.MapClaims{
		"purpose": "sso_exchange",
		"iss":     "cybersentinel-siem",
		"aud":     "guardrail-pam",
		"sub":     "u-8f3c1a92-4b77-4e10-9d55-6a2b8e1f0c34",
		"nonce":   "3f9a1c7e5b204d8fa6c1e93b7d0f4a28",
		"email":   "jdoe@cybersentinel.siem",
		"role":    "L2-Analyst",
		"access":  "read-write",
		"iat":     now.Unix(),
		"nbf":     now.Add(-60 * time.Second).Unix(),
		"exp":     now.Add(120 * time.Second).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	got, err := v.VerifySSOToken(context.Background(), signed)
	if err != nil {
		t.Fatalf("RS256 token REJECTED with no shared secret: %v", err)
	}
	t.Logf("RS256 accepted with an empty secret: sub=%s role=%s access=%s", got.Subject, got.Role, got.Access)

	// And the symmetric path stays shut.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hsSigned, _ := hs.SignedString([]byte("anything"))
	if _, err := v.VerifySSOToken(context.Background(), hsSigned); err == nil {
		t.Fatal("an HS256 token was accepted with no shared secret configured")
	} else {
		t.Logf("HS256 correctly refused: %v", err)
	}
}
