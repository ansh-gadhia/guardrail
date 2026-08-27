package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

const (
	testIssuer   = "cybersentineldlp-siem"
	testAudience = "guardrail-pam"
	testKid      = "siem-2026-08"
)

// ---- helpers ----

type signer struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	return &signer{rsa: rk, ec: ek}
}

// jwksJSON publishes both public keys, the RSA one under testKid.
func (s *signer) jwksJSON(t *testing.T) []byte {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	doc := map[string]any{"keys": []map[string]any{
		{
			"kty": "RSA", "use": "sig", "kid": testKid, "alg": "RS256",
			"n": b64(s.rsa.N.Bytes()),
			"e": b64(big.NewInt(int64(s.rsa.E)).Bytes()),
		},
		{
			"kty": "EC", "use": "sig", "kid": "siem-ec", "crv": "P-256",
			"x": b64(s.ec.X.Bytes()), "y": b64(s.ec.Y.Bytes()),
		},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// claimSet is the shape of a well-formed exchange token; tests mutate one field
// at a time so each case isolates exactly one rule.
func claimSet(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"purpose": iam.SSOPurpose,
		"iss":     testIssuer,
		"aud":     testAudience,
		"sub":     "7f31c0a2-0000-4000-8000-000000000001",
		"nonce":   "9f2c4e",
		"exp":     now.Add(30 * time.Second).Unix(),
		"iat":     now.Unix(),
		"email":   "analyst@corp.example",
		"role":    "L2",
		"access":  "read-write",
	}
}

func signRS256(t *testing.T, s *signer, c jwt.MapClaims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	out, err := tok.SignedString(s.rsa)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out
}

// verifierOn stands a JWKS server up and returns a verifier pointed at it, with
// TLS pinned to the test server's own certificate — which is also the shape a
// real deployment uses against a self-signed SIEM.
func verifierOn(t *testing.T, s *signer) (*SSOTokenVerifier, *httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.jwksJSON(t))
	}))
	t.Cleanup(srv.Close)

	src, err := NewJWKSSource(JWKSConfig{URL: srv.URL, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("jwks source: %v", err)
	}
	// httptest's server uses its own throwaway CA; pin to its client rather than
	// writing the certificate to a temp file.
	src.client = srv.Client()

	return NewSSOVerifier(src, SSOVerifierConfig{
		Issuer: testIssuer, Audience: testAudience,
		ClockLeeway: time.Minute, MaxTokenAge: 10 * time.Minute,
	}), srv, &hits
}

// ---- the happy path ----

func TestSSOVerify_AcceptsWellFormedToken(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)
	now := time.Now()

	a, err := v.VerifySSOToken(context.Background(), signRS256(t, s, claimSet(now), testKid))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if a.Subject != "7f31c0a2-0000-4000-8000-000000000001" {
		t.Errorf("subject: %q", a.Subject)
	}
	if a.Email != "analyst@corp.example" || a.Role != "L2" || a.Access != "read-write" {
		t.Errorf("claims not carried through: %+v", a)
	}
	if a.Nonce != "9f2c4e" {
		t.Errorf("nonce: %q", a.Nonce)
	}
	if a.Leeway != time.Minute {
		t.Errorf("the granted leeway must travel with the assertion, got %s", a.Leeway)
	}
}

// ---- rejections, one rule per case ----

func TestSSOVerify_Rejections(t *testing.T) {
	s := newSigner(t)
	now := time.Now()

	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		want   string
	}{
		{"wrong purpose", func(c jwt.MapClaims) { c["purpose"] = "password_reset" }, "purpose"},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "someone-else" }, "issuer"},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "cybersentinel-dlp" }, "consumer"},
		{"no audience", func(c jwt.MapClaims) { delete(c, "aud") }, "required claim"},
		{"no expiry", func(c jwt.MapClaims) { delete(c, "exp") }, "required claim"},
		{"expired", func(c jwt.MapClaims) { c["exp"] = now.Add(-5 * time.Minute).Unix() }, "expired"},
		{"no nonce", func(c jwt.MapClaims) { delete(c, "nonce") }, "nonce"},
		{
			// A handoff token is not a session token. One claiming hours of life is
			// a misconfiguration, or an attempt to turn a one-shot exchange into a
			// durable credential.
			"lifetime beyond the cap",
			func(c jwt.MapClaims) { c["exp"] = now.Add(24 * time.Hour).Unix() },
			"maximum",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _, _ := verifierOn(t, s)
			c := claimSet(now)
			tc.mutate(c)
			_, err := v.VerifySSOToken(context.Background(), signRS256(t, s, c, testKid))
			if !errors.Is(err, iam.ErrSSOToken) {
				t.Fatalf("want ErrSSOToken, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message should name the fault %q, got %q", tc.want, err)
			}
		})
	}
}

// A token signed by somebody else must not verify, however well-formed it is.
func TestSSOVerify_RejectsForeignSignature(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)
	other := newSigner(t)

	tok := signRS256(t, other, claimSet(time.Now()), testKid)
	if _, err := v.VerifySSOToken(context.Background(), tok); !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}
}

// alg:none is the oldest JWT attack there is. It must be refused as an
// unsupported algorithm, not merely fail somewhere later.
func TestSSOVerify_RejectsAlgNone(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)

	c := claimSet(time.Now())
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, c)
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	_, err = v.VerifySSOToken(context.Background(), raw)
	if !errors.Is(err, iam.ErrSSOToken) || !strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("alg:none must be refused by name, got %v", err)
	}
}

// The algorithm-confusion downgrade: take the issuer's PUBLIC RSA key, use its
// bytes as an HMAC secret, and hope the verifier checks an HS256 signature with
// a key it believed was for RSA. It fails here because the symmetric path uses
// disjoint key material and is switched off entirely unless a shared secret is
// configured — and because the parser is only ever handed the single routed
// algorithm, never the union of the two families.
func TestSSOVerify_RejectsAlgorithmConfusion(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claimSet(time.Now()))
	forged.Header["kid"] = testKid
	raw, err := forged.SignedString(s.rsa.N.Bytes())
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	_, err = v.VerifySSOToken(context.Background(), raw)
	if !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}
	if !strings.Contains(err.Error(), "symmetric signing is not accepted") {
		t.Errorf("want the symmetric path refused, got %q", err)
	}
}

// Even with a shared secret configured for a legacy issuer, the two paths must
// stay separate: an HS256 token signed with the RSA public key still fails,
// because that key is not the secret.
func TestSSOVerify_SymmetricPathUsesDisjointKeyMaterial(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)
	v.secret = []byte("a-legacy-shared-secret-of-sufficient-length")

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claimSet(time.Now()))
	forged.Header["kid"] = testKid
	raw, _ := forged.SignedString(s.rsa.N.Bytes())
	if _, err := v.VerifySSOToken(context.Background(), raw); !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}

	// The genuine symmetric token still works, so the path is live and it is the
	// key material — not the algorithm family — doing the rejecting above.
	good := jwt.NewWithClaims(jwt.SigningMethodHS256, claimSet(time.Now()))
	rawGood, _ := good.SignedString(v.secret)
	if _, err := v.VerifySSOToken(context.Background(), rawGood); err != nil {
		t.Fatalf("genuine HS256 token should verify: %v", err)
	}
}

// A kid the key set does not publish is the TOKEN's fault (401), never reported
// as a server outage — otherwise a client retries a forgery forever inside
// GuardRail's own error budget.
func TestSSOVerify_UnknownKidIsATokenFault(t *testing.T) {
	s := newSigner(t)
	v, _, _ := verifierOn(t, s)

	tok := signRS256(t, s, claimSet(time.Now()), "a-kid-the-siem-never-published")
	_, err := v.VerifySSOToken(context.Background(), tok)
	if !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("unknown kid must be 401-shaped (ErrSSOToken), got %v", err)
	}
	if errors.Is(err, iam.ErrSSOUnavailable) {
		t.Fatal("unknown kid must not be reported as a server outage")
	}
}

// An unknown kid forces exactly ONE refetch, then the cooldown holds. Without
// it, a stream of unknown-kid tokens turns GuardRail into a request amplifier
// aimed at the SIEM's key endpoint.
func TestSSOVerify_UnknownKidRefetchIsRateLimited(t *testing.T) {
	s := newSigner(t)
	v, _, hits := verifierOn(t, s)
	tok := signRS256(t, s, claimSet(time.Now()), "rotated-away")

	for range 5 {
		_, _ = v.VerifySSOToken(context.Background(), tok)
	}
	// One fetch to populate the cache, one forced by the first unknown kid.
	if *hits > 2 {
		t.Fatalf("unknown-kid refetch is not rate limited: %d fetches", *hits)
	}
}

// An unreachable key set with nothing cached is GuardRail's outage (503), and it
// must fail CLOSED: a key set that could not be fetched is not evidence that a
// signature is good.
func TestSSOVerify_UnreachableJWKSFailsClosed(t *testing.T) {
	s := newSigner(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := NewJWKSSource(JWKSConfig{URL: srv.URL, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	src.client = srv.Client()
	v := NewSSOVerifier(src, SSOVerifierConfig{Issuer: testIssuer, Audience: testAudience})

	_, err = v.VerifySSOToken(context.Background(), signRS256(t, s, claimSet(time.Now()), testKid))
	if !errors.Is(err, iam.ErrSSOUnavailable) {
		t.Fatalf("want ErrSSOUnavailable, got %v", err)
	}
}

// With no key material at all the answer is "not configured" (503), which is a
// different sentence from "your token is bad".
func TestSSOVerify_NotConfigured(t *testing.T) {
	v := NewSSOVerifier(nil, SSOVerifierConfig{Issuer: testIssuer, Audience: testAudience})
	if v.Configured() {
		t.Fatal("a verifier with no keys and no secret must not report itself configured")
	}
	if _, err := v.VerifySSOToken(context.Background(), "x.y.z"); !errors.Is(err, iam.ErrSSONotConfigured) {
		t.Fatalf("want ErrSSONotConfigured, got %v", err)
	}
}
