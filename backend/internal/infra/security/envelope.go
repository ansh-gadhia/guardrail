package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/guardrail/guardrail/internal/domain/vault"
)

// EnvelopeEncryptor implements vault.Encryptor with AES-256-GCM envelope
// encryption: a fresh 256-bit Data-Encryption-Key (DEK) encrypts each secret,
// and the DEK is wrapped by the active Key-Encryption-Key (KEK) from the
// KeyProvider. Rotating the KEK re-wraps DEKs without re-encrypting secrets.
type EnvelopeEncryptor struct {
	keys vault.KeyProvider
}

// NewEnvelopeEncryptor builds an encryptor over a key provider.
func NewEnvelopeEncryptor(keys vault.KeyProvider) *EnvelopeEncryptor {
	return &EnvelopeEncryptor{keys: keys}
}

const dekLen = 32 // 256-bit DEK

// Seal encrypts plaintext under a fresh DEK and wraps the DEK with the active KEK.
func (e *EnvelopeEncryptor) Seal(plaintext []byte) (vault.SealedSecret, error) {
	kekID, kek, err := e.keys.Active()
	if err != nil {
		return vault.SealedSecret{}, err
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return vault.SealedSecret{}, fmt.Errorf("security: generate dek: %w", err)
	}

	ciphertext, secretNonce, err := gcmSeal(dek, plaintext)
	if err != nil {
		return vault.SealedSecret{}, err
	}
	wrapped, dekNonce, err := gcmSeal(kek, dek)
	if err != nil {
		return vault.SealedSecret{}, err
	}
	return vault.SealedSecret{
		KEKID: kekID, Ciphertext: ciphertext, SecretNonce: secretNonce,
		DEKWrapped: wrapped, DEKNonce: dekNonce,
	}, nil
}

// Open unwraps the DEK with the recorded KEK and decrypts the secret.
func (e *EnvelopeEncryptor) Open(s vault.SealedSecret) ([]byte, error) {
	kek, err := e.keys.Get(s.KEKID)
	if err != nil {
		return nil, err
	}
	dek, err := gcmOpen(kek, s.DEKNonce, s.DEKWrapped)
	if err != nil {
		return nil, fmt.Errorf("security: unwrap dek: %w", err)
	}
	plaintext, err := gcmOpen(dek, s.SecretNonce, s.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("security: open secret: %w", err)
	}
	return plaintext, nil
}

// Rewrap re-encrypts the DEK under the active KEK, leaving the secret ciphertext
// untouched. Used by the KEK-rotation job.
func (e *EnvelopeEncryptor) Rewrap(s vault.SealedSecret) (vault.SealedSecret, error) {
	oldKEK, err := e.keys.Get(s.KEKID)
	if err != nil {
		return vault.SealedSecret{}, err
	}
	dek, err := gcmOpen(oldKEK, s.DEKNonce, s.DEKWrapped)
	if err != nil {
		return vault.SealedSecret{}, fmt.Errorf("security: unwrap dek: %w", err)
	}
	newID, newKEK, err := e.keys.Active()
	if err != nil {
		return vault.SealedSecret{}, err
	}
	wrapped, dekNonce, err := gcmSeal(newKEK, dek)
	if err != nil {
		return vault.SealedSecret{}, err
	}
	s.KEKID = newID
	s.DEKWrapped = wrapped
	s.DEKNonce = dekNonce
	return s, nil
}

// Encrypt seals a small secret into a self-describing opaque blob (a
// JSON-encoded SealedSecret). It satisfies iam.Cipher so MFA secrets are
// protected by the same envelope scheme as the credential vault.
func (e *EnvelopeEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	sealed, err := e.Seal(plaintext)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealed)
}

// Decrypt opens a blob produced by Encrypt.
func (e *EnvelopeEncryptor) Decrypt(blob []byte) ([]byte, error) {
	var sealed vault.SealedSecret
	if err := json.Unmarshal(blob, &sealed); err != nil {
		return nil, fmt.Errorf("security: decode sealed blob: %w", err)
	}
	return e.Open(sealed)
}

// gcmSeal encrypts plaintext with key using AES-256-GCM and a random nonce.
func gcmSeal(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("security: generate nonce: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// gcmOpen decrypts ciphertext with key and nonce using AES-256-GCM.
func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
