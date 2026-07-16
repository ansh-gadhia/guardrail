// Package security implements the IAM security ports: Argon2id password hashing,
// opaque refresh-token generation, and JWT access-token issuance. These are the
// concrete adapters wired into the application layer.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost parameters. Defaults follow OWASP guidance
// (>= 19 MiB memory, and a small iteration count) and are encoded into each hash
// so parameters can be tuned over time without breaking existing hashes.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params returns sensible production defaults.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Argon2Hasher implements iam.PasswordHasher using Argon2id.
type Argon2Hasher struct {
	p Argon2Params
}

// NewArgon2Hasher builds a hasher with the given parameters.
func NewArgon2Hasher(p Argon2Params) *Argon2Hasher { return &Argon2Hasher{p: p} }

var errInvalidHash = errors.New("security: invalid argon2 hash encoding")

// Hash returns the PHC-formatted Argon2id encoding of the password.
func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.p.Iterations, h.p.Memory, h.p.Parallelism, h.p.KeyLength)

	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.Memory, h.p.Iterations, h.p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify checks a password against an encoded hash in constant time.
func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	p, salt, key, err := decodeArgon2(encodedHash)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeEq(int32(len(other)), int32(len(key))) == 0 {
		return false, nil
	}
	return subtle.ConstantTimeCompare(other, key) == 1, nil
}

// NeedsRehash reports whether the stored hash's parameters differ from current
// policy (weaker), so it can be upgraded on next successful login.
func (h *Argon2Hasher) NeedsRehash(encodedHash string) bool {
	p, _, _, err := decodeArgon2(encodedHash)
	if err != nil {
		return true
	}
	return p.Memory < h.p.Memory || p.Iterations < h.p.Iterations || p.Parallelism < h.p.Parallelism
}

// decodeArgon2 parses a PHC Argon2id string into its parameters and byte fields.
func decodeArgon2(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, errInvalidHash
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("security: incompatible argon2 version %d", version)
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, errInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, errInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, errInvalidHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
