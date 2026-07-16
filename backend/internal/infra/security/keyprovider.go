package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// EnvKeyProvider derives a single 256-bit KEK from the master key supplied in
// the environment (GUARDRAIL_MASTER_KEY), using HKDF-SHA256. It implements
// vault.KeyProvider. Additional providers (KMS, Vault, CyberArk) implement the
// same interface without changing the vault service.
type EnvKeyProvider struct {
	id  string
	key []byte
}

// EnvKEKID is the identifier recorded against secrets sealed by this provider.
const EnvKEKID = "env:1"

// NewEnvKeyProvider derives the KEK from the master secret. The derivation binds
// the key to a fixed info label so rotating the label rotates the effective KEK.
func NewEnvKeyProvider(masterKey string) (*EnvKeyProvider, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("security: master key must be at least 32 bytes")
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(masterKey), []byte("guardrail-kek-salt-v1"), []byte("guardrail-vault-kek"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("security: derive kek: %w", err)
	}
	return &EnvKeyProvider{id: EnvKEKID, key: key}, nil
}

// Active returns the current KEK id and key.
func (p *EnvKeyProvider) Active() (string, []byte, error) { return p.id, p.key, nil }

// Get returns the key for a KEK id. The env provider only knows its own key.
func (p *EnvKeyProvider) Get(id string) ([]byte, error) {
	if id != p.id {
		return nil, fmt.Errorf("security: unknown KEK id %q", id)
	}
	return p.key, nil
}
