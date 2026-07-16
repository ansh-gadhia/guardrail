package vault

import "errors"

// ErrNotFound is returned when a credential does not exist in scope.
var ErrNotFound = errors.New("vault: not found")

// ErrInjectionMismatch is returned when a credential's injection method cannot
// authenticate the device's protocol — HTTP Basic auth over SSH, say. Refused at
// the API rather than left for the gateway, because a credential that cannot
// authenticate is not a preference: the device reads as configured and refuses
// every connection, and the operator learns about it at Connect.
var ErrInjectionMismatch = errors.New("vault: injection method cannot authenticate this protocol")

// ErrSecretRequired is returned when creating a device's first credential
// without any secret material to seal.
var ErrSecretRequired = errors.New("vault: secret is required")

// KeyProvider supplies Key-Encryption-Keys (KEKs). The env-backed provider ships
// first; KMS / HashiCorp Vault / CyberArk providers implement the same port
// later without touching callers.
type KeyProvider interface {
	// Active returns the KEK id and 32-byte key used for new encryptions.
	Active() (id string, key []byte, err error)
	// Get returns the 32-byte key for a specific KEK id (to open/rewrap older
	// ciphertext during rotation).
	Get(id string) (key []byte, err error)
}

// Encryptor seals and opens secrets using envelope encryption on top of a
// KeyProvider. Implementations use AES-256-GCM with per-operation random nonces.
type Encryptor interface {
	// Seal encrypts plaintext, generating a fresh DEK wrapped by the active KEK.
	Seal(plaintext []byte) (SealedSecret, error)
	// Open recovers the plaintext from a sealed secret.
	Open(s SealedSecret) ([]byte, error)
	// Rewrap re-encrypts the DEK under the active KEK without changing the
	// secret ciphertext — used for KEK rotation.
	Rewrap(s SealedSecret) (SealedSecret, error)
}
