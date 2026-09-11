package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// BindingSigner proves that a credential binding was written by GuardRail.
//
// The vault protects the secret; this protects the sentence "that secret is for
// this device, for this person". Those are different claims and the ciphertext
// was only ever making the first one — device_credentials and group_credentials
// are join rows with nothing but foreign keys in them, so anyone who could write
// one could point a device they reach at a credential they may not have. See
// migrations/0035_binding_integrity.up.sql.
//
// The key is derived from the vault master key rather than configured, so this
// adds nothing for an operator to set, rotate or lose. A distinct HKDF info
// label keeps it disjoint from the vault KEK: the two are used for different
// jobs and neither should be usable in the other's place.
type BindingSigner struct{ key []byte }

// bindingInfo separates this subkey from the vault KEK derived from the same
// master key. Changing it invalidates every signature, which the startup
// backfill would then silently repair — so do not change it.
const bindingInfo = "guardrail-binding-mac-v1"

// NewBindingSigner derives the binding subkey from the master key.
func NewBindingSigner(masterKey string) (*BindingSigner, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("security: master key must be at least 32 bytes")
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(masterKey), []byte("guardrail-kek-salt-v1"), []byte(bindingInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("security: derive binding key: %w", err)
	}
	return &BindingSigner{key: key}, nil
}

// Sign returns the MAC for a binding.
//
// scope is the table the binding lives in ("device" or "group"), so a row cannot
// be lifted from one to the other and keep a valid signature. userID is the zero
// UUID for a shared binding, which is a different string from any real user id
// and therefore a different MAC — a shared binding cannot be re-labelled as a
// person's, or the reverse.
func (b *BindingSigner) Sign(scope string, parent, credentialID, userID uuid.UUID) []byte {
	m := hmac.New(sha256.New, b.key)
	// Length-prefixed by construction: UUIDs are fixed width and the scope is
	// terminated, so no two distinct bindings can produce the same input string.
	m.Write([]byte(scope))
	m.Write([]byte{0})
	m.Write(parent[:])
	m.Write(credentialID[:])
	m.Write(userID[:])
	return m.Sum(nil)
}

// Verify reports whether mac is the signature for this binding, in constant
// time. An absent signature is NOT valid: a caller that wants to tolerate one
// has to say so itself, so that "unsigned" can never quietly become "trusted".
func (b *BindingSigner) Verify(mac []byte, scope string, parent, credentialID, userID uuid.UUID) bool {
	if len(mac) == 0 {
		return false
	}
	return hmac.Equal(mac, b.Sign(scope, parent, credentialID, userID))
}

// auditChainInfo separates the audit-chain subkey from the vault KEK and the
// binding key, all three derived from the same master key. Changing it
// invalidates every keyed chain hash, so it is permanent.
const auditChainInfo = "guardrail-audit-chain-v1"

// NewAuditChainKey derives the key that makes the audit chain tamper-EVIDENT
// rather than merely tamper-detectable-by-someone-without-write-access.
//
// The chain was a plain SHA-256 over (previous hash ‖ canonical event). That
// detects an edit by anyone who cannot recompute the rest of the chain — but
// recomputing it needs nothing except the algorithm, which is in this file. So
// anyone with UPDATE on audit_events could rewrite history and repair the chain
// behind them, and the "tamper-evident" claim rested entirely on the database
// grant that withholds UPDATE from the application role.
//
// That grant is a good control and it is still there. It is not cryptography,
// and it does not survive a database compromise, a restore from a doctored
// backup, or anybody with the owner role. An HMAC does: forging a chain now
// needs a key that lives only in the API's memory.
func NewAuditChainKey(masterKey string) ([]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("security: master key must be at least 32 bytes")
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(masterKey), []byte("guardrail-kek-salt-v1"), []byte(auditChainInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("security: derive audit chain key: %w", err)
	}
	return key, nil
}
