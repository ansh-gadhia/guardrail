package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// refreshTokenBytes is the entropy of an opaque refresh token (256 bits).
const refreshTokenBytes = 32

// GenerateRefreshToken returns a new opaque refresh token (URL-safe base64) and
// its SHA-256 hash. Only the hash is persisted; the raw token is returned to the
// client once and never stored.
func GenerateRefreshToken() (raw string, hash []byte, err error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("security: read refresh token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashRefreshToken(raw), nil
}

// HashRefreshToken hashes a raw refresh token for storage/lookup. SHA-256 is
// appropriate here because the token is high-entropy random (not a low-entropy
// password), so a slow KDF is unnecessary.
func HashRefreshToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
