package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// CookieSigner produces and verifies HMAC-signed, tamper-evident cookie values.
// It is used for the short-lived OIDC transaction cookie (state, nonce, PKCE
// verifier) that must survive the redirect to the IdP without server-side state.
type CookieSigner struct{ key []byte }

// NewCookieSigner derives a signing key from the JWT signing key, domain-
// separated so it never collides with the access-token or MFA-challenge signers.
func NewCookieSigner(signingKey string) *CookieSigner {
	sum := sha256.Sum256([]byte("guardrail/cookie-signer\x00" + signingKey))
	return &CookieSigner{key: sum[:]}
}

// Sign returns "base64(value).sig".
func (s *CookieSigner) Sign(value string) string {
	enc := base64.RawURLEncoding.EncodeToString([]byte(value))
	return enc + "." + s.sign(enc)
}

// Verify checks the signature and returns the original value.
func (s *CookieSigner) Verify(signed string) (string, bool) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(s.sign(parts[0])), []byte(parts[1])) != 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func (s *CookieSigner) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
