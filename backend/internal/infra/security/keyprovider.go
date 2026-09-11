package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// EnvKeyProvider derives KEKs from master keys supplied in the environment
// (GUARDRAIL_MASTER_KEY, and optionally GUARDRAIL_MASTER_KEY_PREVIOUS) using
// HKDF-SHA256. It implements vault.KeyProvider.
//
// # THE KEK ID IS DERIVED FROM THE KEY, NOT FIXED
//
// It used to be the constant "env:1", and that one detail made key rotation
// silently destructive. Changing GUARDRAIL_MASTER_KEY produced a DIFFERENT key
// under the SAME id: every stored row still said kek_id='env:1', Get returned
// the new key for it, and AES-GCM authentication failed. Every vault credential
// and every TOTP secret became permanently unopenable, with no warning and no
// way back — and nothing in the product could even tell you which key a row had
// been sealed under.
//
// Deriving the id from the key fixes both halves. A changed master key produces
// a new id, so old rows stay identifiable and can be found and re-wrapped; and
// a row whose id names a key this process does not hold fails with "unknown KEK
// id" instead of a corrupt-looking authentication error.
//
// LEGACY "env:1"
//
// Rows sealed before this change carry the old constant, which names no
// particular key — it means "whatever master key was configured at the time".
// Get resolves it against the keys this process actually holds, current first,
// then previous. That keeps existing deployments working, and `guardrail
// rotate-kek` moves those rows onto a derived id so the ambiguity goes away.
type EnvKeyProvider struct {
	id  string
	key []byte
	// prevID/prev are the superseded key, present only when
	// GUARDRAIL_MASTER_KEY_PREVIOUS is set. They exist so a rotation can open
	// what the old key sealed.
	prevID string
	prev   []byte
}

// LegacyEnvKEKID is the fixed identifier used before ids were derived. It names
// no particular key; see the type comment.
const LegacyEnvKEKID = "env:1"

// EnvKEKID is retained for callers that referred to the old constant.
//
// Deprecated: an id is now derived per key. Use Active().
const EnvKEKID = LegacyEnvKEKID

// kekSalt and kekInfo are the HKDF parameters for the vault KEK. Changing
// either changes every derived key and therefore every id, which would strand
// all existing ciphertext — so they are constants, not configuration.
const (
	kekSalt = "guardrail-kek-salt-v1"
	kekInfo = "guardrail-vault-kek"
)

// deriveKEK produces the 32-byte KEK for a master key.
func deriveKEK(masterKey string) ([]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("security: master key must be at least 32 bytes")
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(masterKey), []byte(kekSalt), []byte(kekInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("security: derive kek: %w", err)
	}
	return key, nil
}

// kekIDFor names a KEK by a truncated hash of the key itself.
//
// A hash of the KEK, never of the master key: this string is written to the
// database and read by anyone who can see a credential row, and it must not be
// a hint about the secret it came from. Twelve hex characters is 48 bits, which
// is far more than enough to tell apart the handful of keys one deployment ever
// has, and it is not reversible.
func kekIDFor(kek []byte) string {
	sum := sha256.Sum256(kek)
	return "env:" + hex.EncodeToString(sum[:6])
}

// NewEnvKeyProvider derives the KEK from the master secret.
func NewEnvKeyProvider(masterKey string) (*EnvKeyProvider, error) {
	return NewEnvKeyProviderWithPrevious(masterKey, "")
}

// NewEnvKeyProviderWithPrevious also accepts the superseded master key, so a
// rotation can open what it sealed. An empty previous key is the normal case.
func NewEnvKeyProviderWithPrevious(masterKey, previousKey string) (*EnvKeyProvider, error) {
	key, err := deriveKEK(masterKey)
	if err != nil {
		return nil, err
	}
	p := &EnvKeyProvider{id: kekIDFor(key), key: key}
	if previousKey == "" {
		return p, nil
	}
	prev, err := deriveKEK(previousKey)
	if err != nil {
		return nil, fmt.Errorf("security: previous master key: %w", err)
	}
	if subtle.ConstantTimeCompare(prev, key) == 1 {
		// Not an error worth failing a boot over, but it is certainly a mistake:
		// rotation would have nothing to move.
		return nil, errors.New("security: the previous master key is the same as the current one")
	}
	p.prevID, p.prev = kekIDFor(prev), prev
	return p, nil
}

// Active returns the current KEK id and key.
func (p *EnvKeyProvider) Active() (string, []byte, error) { return p.id, p.key, nil }

// Previous returns the superseded KEK id, or "" when none is configured. It is
// what a rotation asks for to know which rows to move.
func (p *EnvKeyProvider) Previous() string { return p.prevID }

// Get returns the key for a KEK id.
//
// The legacy id is special: it names no particular key, so it is tried against
// everything this process holds. Every other id names exactly one key, and a
// miss is an error rather than a guess — trying keys until one works is how a
// caller ends up decrypting with a key nobody chose.
func (p *EnvKeyProvider) Get(id string) ([]byte, error) {
	switch id {
	case p.id:
		return p.key, nil
	case p.prevID:
		if p.prev != nil {
			return p.prev, nil
		}
	case LegacyEnvKEKID:
		// Ambiguous by construction. Current key first: on a deployment that has
		// never rotated, that is the one that sealed these rows.
		return p.key, nil
	}
	return nil, fmt.Errorf("security: unknown KEK id %q", id)
}

// LegacyKeys returns every key that a row marked with the legacy id might have
// been sealed under, in the order worth trying.
//
// Separate from Get because the ambiguity belongs to the caller doing the
// rotation, not to the decryption path. Get answers "which key is this", and
// for the legacy id the honest answer is "one of these"; a resolver that
// silently tried them all would be deciding, on its own, that a secret opened
// by an unexpected key is fine.
func (p *EnvKeyProvider) LegacyKeys() [][]byte {
	if p.prev == nil {
		return [][]byte{p.key}
	}
	return [][]byte{p.key, p.prev}
}
