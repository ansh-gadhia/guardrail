// Package vault is the credential-vault bounded context. Secrets are protected
// with envelope encryption and are never exposed in plaintext through any read
// path; the domain models the ciphertext envelope and the ports needed to seal,
// open, and rotate it.
package vault

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CredentialType enumerates the kinds of secret material stored.
type CredentialType string

const (
	TypePassword    CredentialType = "password"
	TypeAPIKey      CredentialType = "api_key"
	TypeCertificate CredentialType = "certificate"
	TypeClientCert  CredentialType = "client_cert"
)

// InjectionMethod describes how the secret is presented to the target device by
// the proxy gateway at connect time.
type InjectionMethod string

const (
	InjectForm   InjectionMethod = "form"   // fill a login form
	InjectBasic  InjectionMethod = "basic"  // HTTP Basic auth
	InjectHeader InjectionMethod = "header" // inject an Authorization/API header
	InjectNone   InjectionMethod = "none"
	// InjectSSHPassword and InjectSSHKey authenticate a terminal session; the key
	// variant's secret is the PEM private key itself.
	InjectSSHPassword InjectionMethod = "ssh-password"
	InjectSSHKey      InjectionMethod = "ssh-key"
	// InjectPassword is a desktop (RDP/VNC) username+password, handed to guacd in
	// its connect handshake.
	InjectPassword InjectionMethod = "password"
)

// injectionsByScheme lists the methods that can actually authenticate each
// protocol. A method that cannot is not a preference to be tolerated: the three
// HTTP methods have no meaning over SSH, and binding one produces a device that
// looks configured and refuses every connection.
//
// This existed only in each gateway's head before, which is how a real device was
// registered with HTTP Basic auth over SSH: the console offered the web methods
// whatever the protocol, the vault stored it, and the failure waited until
// someone pressed Connect.
var injectionsByScheme = map[string][]InjectionMethod{
	"https": {InjectBasic, InjectHeader, InjectForm},
	"http":  {InjectBasic, InjectHeader, InjectForm},
	"ssh":   {InjectSSHPassword, InjectSSHKey},
	"rdp":   {InjectPassword},
	"vnc":   {InjectPassword},
	// Telnet has no authentication of its own: guacd types the credential at the
	// device's login prompt. So it is a password, and only a password — there is
	// no key exchange to offer, however much the device looks like an SSH host.
	"telnet": {InjectPassword},
}

// InjectionsFor returns the methods that can authenticate this protocol, in the
// order a console should offer them. An unknown scheme gets nothing, so a new
// protocol has to say what it accepts rather than inherit the web's.
func InjectionsFor(scheme string) []InjectionMethod {
	return append([]InjectionMethod(nil), injectionsByScheme[scheme]...)
}

// InjectionValidFor reports whether m can authenticate scheme. InjectNone is
// accepted everywhere: it means "there is no secret to inject", which is a
// coherent thing to say about any protocol.
func InjectionValidFor(m InjectionMethod, scheme string) bool {
	if m == InjectNone {
		return true
	}
	for _, ok := range injectionsByScheme[scheme] {
		if ok == m {
			return true
		}
	}
	return false
}

// DefaultInjectionFor is the method a console lands on for a protocol when the
// caller says nothing: the first one it can use.
func DefaultInjectionFor(scheme string) InjectionMethod {
	if ms := injectionsByScheme[scheme]; len(ms) > 0 {
		return ms[0]
	}
	return InjectNone
}

// SealedSecret is the envelope-encrypted representation persisted in the vault.
// No field reveals plaintext without the KEK.
type SealedSecret struct {
	KEKID       string
	Ciphertext  []byte // AES-256-GCM(plaintext, DEK, SecretNonce)
	SecretNonce []byte
	DEKWrapped  []byte // AES-256-GCM(DEK, KEK, DEKNonce)
	DEKNonce    []byte
}

// Credential is a vault entry. The plaintext secret is only ever present in the
// Secret field transiently (on create/rotate input and on resolve output); it is
// never persisted or serialized to clients.
type Credential struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Type           CredentialType
	Username       string
	Injection      InjectionMethod
	Sealed         SealedSecret
	Metadata       map[string]any
	RotatedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// CredentialRepository persists sealed credentials (tenant-scoped).
type CredentialRepository interface {
	Create(ctx context.Context, scope Scope, c *Credential) error
	Update(ctx context.Context, scope Scope, c *Credential) error
	GetByID(ctx context.Context, scope Scope, id uuid.UUID) (*Credential, error)
	List(ctx context.Context, scope Scope, limit int) ([]Credential, error)
	SoftDelete(ctx context.Context, scope Scope, id uuid.UUID) error
	// BindToDevice associates a credential with a device.
	BindToDevice(ctx context.Context, scope Scope, deviceID, credentialID uuid.UUID, isDefault bool) error
	// ResolveForDevice returns the default (or first) credential bound to a
	// device, for just-in-time injection by the gateway.
	ResolveForDevice(ctx context.Context, scope Scope, deviceID uuid.UUID) (*Credential, error)
	// HasCredentialForDevice reports whether a device has at least one bound,
	// non-deleted credential. It performs no decryption and emits no audit event,
	// so it is safe to call as a fail-closed pre-flight before a connect.
	HasCredentialForDevice(ctx context.Context, scope Scope, deviceID uuid.UUID) (bool, error)
	// DeviceIDsWithCredential returns the subset of the given device IDs that have
	// at least one bound, non-deleted credential (for list projections).
	DeviceIDsWithCredential(ctx context.Context, scope Scope, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error)
	// ListByKEK returns credentials sealed under a given KEK (for rotation).
	ListByKEK(ctx context.Context, kekID string, limit int) ([]Credential, error)
}

// Scope is the tenant scope for vault operations (mirrors iam.TenantScope to
// keep the vault context independent of IAM).
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}
