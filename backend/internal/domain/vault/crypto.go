package vault

import (
	"errors"

	"github.com/google/uuid"
)

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

// ErrInvalid is returned when a vault request is malformed — a per-user account
// that names neither a device nor a group, say.
var ErrInvalid = errors.New("vault: invalid")

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

// ErrBindingUnsigned is returned when a credential binding carries no valid
// signature. It is deliberately distinct from ErrNotFound: "this row was not
// written by GuardRail" and "there is no row" are different facts, and an
// operator chasing a refused connection needs to be able to tell them apart.
var ErrBindingUnsigned = errors.New("vault: credential binding is not signed by this deployment")

// BindingSigner proves that a credential binding — the row saying "this secret
// is for this device, for this person" — was written by GuardRail.
//
// The vault protects the secret itself. This protects the mapping, which the
// ciphertext never covered: device_credentials and group_credentials are join
// rows of foreign keys, so anyone able to write one could aim a device they
// reach at a credential they may not have, and the gateway would inject it.
//
// Implemented in infra/security over a subkey of the vault master key, so it
// adds nothing for an operator to configure.
type BindingSigner interface {
	// Sign returns the MAC for a binding. scope distinguishes the table the row
	// lives in; userID is the zero UUID for a shared binding.
	Sign(scope string, parent, credentialID, userID uuid.UUID) []byte
	// Verify reports whether mac matches, in constant time. An absent MAC is
	// never valid.
	Verify(mac []byte, scope string, parent, credentialID, userID uuid.UUID) bool
}

// Binding scopes. Values are part of the signed input, so changing one
// invalidates every signature in that table.
const (
	BindingScopeDevice = "device"
	BindingScopeGroup  = "group"
)

// Encryptor seals and opens secrets using envelope encryption on top of a
// KeyProvider. Implementations use AES-256-GCM with per-operation random nonces.
type Encryptor interface {
	// Seal encrypts plaintext, generating a fresh DEK wrapped by the active KEK.
	//
	// aad is bound into the authentication tag, so the result opens only when
	// the same bytes are supplied again. Callers pass CredentialAAD; nil is
	// accepted and records AADNone, which exists for the re-seal path and for
	// secrets that genuinely have no identity to bind to.
	Seal(plaintext, aad []byte) (SealedSecret, error)
	// Open recovers the plaintext from a sealed secret.
	//
	// aad must be what Seal was given. It is ignored for a SealedSecret whose
	// AADVersion is AADNone, because no tag over it exists.
	Open(s SealedSecret, aad []byte) ([]byte, error)
	// Rewrap re-encrypts the DEK under the active KEK without changing the
	// secret ciphertext — used for KEK rotation.
	Rewrap(s SealedSecret) (SealedSecret, error)
}
