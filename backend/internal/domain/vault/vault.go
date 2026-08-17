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

// Binding is a credential attached to a device or to an asset group, optionally
// owned by one person. It carries no secret material — it is the projection the
// console lists and the provenance the broker reasons about.
type Binding struct {
	CredentialID uuid.UUID
	// Exactly one of DeviceID / GroupID is set: a binding either names one
	// device or the subtree under one asset group.
	DeviceID *uuid.UUID
	GroupID  *uuid.UUID
	// UserID is the person this credential logs in as. Nil is the device's
	// shared credential — the only kind that existed before per-user accounts.
	UserID         *uuid.UUID
	CredentialName string
	Username       string
	Injection      InjectionMethod
	RotatedAt      *time.Time
	CreatedAt      time.Time
	// UserEmail and GroupName are denormalized for display so the console does
	// not have to issue a lookup per row.
	UserEmail string
	GroupName string
}

// Resolution is a credential together with where it came from.
//
// Provenance is not decoration. The approval gate exempts a device's owner from
// asking permission on their own device, and that exemption has to stop at
// credentials the owner never supplied: a device dropped into the right asset
// group inherits secrets its creator has never seen, and an unqualified owner
// bypass would turn "register a device" into an ungated path to the vault.
type Resolution struct {
	Credential *Credential
	// Inherited reports that the credential came from an asset group rather
	// than from the device itself.
	Inherited bool
	// PerUser reports that the credential belongs to the connecting user rather
	// than being the device's shared login.
	PerUser bool
	// GroupID names the group a binding was inherited from, when Inherited.
	GroupID *uuid.UUID
}

// CredentialRepository persists sealed credentials (tenant-scoped).
type CredentialRepository interface {
	Create(ctx context.Context, scope Scope, c *Credential) error
	Update(ctx context.Context, scope Scope, c *Credential) error
	GetByID(ctx context.Context, scope Scope, id uuid.UUID) (*Credential, error)
	List(ctx context.Context, scope Scope, limit int) ([]Credential, error)
	SoftDelete(ctx context.Context, scope Scope, id uuid.UUID) error

	// BindToDevice attaches a credential to a device. A nil userID makes it the
	// device's shared credential; a non-nil one makes it that person's account.
	BindToDevice(ctx context.Context, scope Scope, deviceID, credentialID uuid.UUID, userID *uuid.UUID) error
	// UnbindFromDevice removes a binding. A nil userID removes the shared one.
	UnbindFromDevice(ctx context.Context, scope Scope, deviceID uuid.UUID, userID *uuid.UUID) error
	// BindToGroup attaches a person's credential to every device in an asset
	// group's subtree. Group bindings are always owned: "this secret works on
	// everything under here, for everyone" is a much larger claim and is
	// deliberately not expressible.
	BindToGroup(ctx context.Context, scope Scope, groupID, credentialID, userID uuid.UUID) error
	// UnbindFromGroup removes a person's binding from a group.
	UnbindFromGroup(ctx context.Context, scope Scope, groupID, userID uuid.UUID) error

	// ResolveForDevice returns the credential to inject for this user on this
	// device, honouring the device's credential_mode.
	//
	// The mode is applied HERE, in one query, rather than by each caller. A
	// caller that forgot it would pass a per-user device's fail-closed check on
	// the strength of somebody else's credential, create the session, emit the
	// audit event, and only fail at injection time — in front of the user, with
	// a session row already written.
	ResolveForDevice(ctx context.Context, scope Scope, deviceID, userID uuid.UUID) (*Resolution, error)
	// HasCredentialForDevice reports whether this user would get a credential on
	// this device. It performs no decryption and emits no audit event, so it is
	// safe as a fail-closed pre-flight before a connect. It applies
	// credential_mode for the same reason ResolveForDevice does.
	HasCredentialForDevice(ctx context.Context, scope Scope, deviceID, userID uuid.UUID) (bool, error)
	// DeviceIDsProvisioned returns the subset of the given device IDs that
	// SOMEBODY can connect to — a shared credential, or at least one per-user
	// account.
	//
	// Deliberately not the same question as HasCredentialForDevice. An estate
	// listing asks "is this device set up", and answering it per viewer would
	// paint forty properly-provisioned per-user devices as unconfigured for the
	// administrator who happens not to hold an account on any of them. Who *you*
	// connect as is answered by ResolveForDevice.
	DeviceIDsProvisioned(ctx context.Context, scope Scope, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error)

	// ListDeviceBindings returns every binding attached directly to a device.
	ListDeviceBindings(ctx context.Context, scope Scope, deviceID uuid.UUID) ([]Binding, error)
	// ListInheritedBindings returns the group bindings a device inherits,
	// nearest ancestor first.
	ListInheritedBindings(ctx context.Context, scope Scope, deviceID uuid.UUID) ([]Binding, error)
	// ListGroupBindings returns every binding attached to an asset group.
	ListGroupBindings(ctx context.Context, scope Scope, groupID uuid.UUID) ([]Binding, error)
	// ListUserBindings returns every binding owned by one person, for
	// offboarding and for the per-user account listing.
	ListUserBindings(ctx context.Context, scope Scope, userID uuid.UUID) ([]Binding, error)
	// CredentialIDsForUser returns the credentials owned by one person, used to
	// retire them when the account is deactivated.
	CredentialIDsForUser(ctx context.Context, scope Scope, userID uuid.UUID) ([]uuid.UUID, error)
	// StaleCredentials returns credentials whose secret has not been rotated
	// since `before`, for the rotation-age surface.
	StaleCredentials(ctx context.Context, scope Scope, before time.Time, limit int) ([]Credential, error)

	// ListByKEK returns credentials sealed under a given KEK (for rotation).
	ListByKEK(ctx context.Context, kekID string, limit int) ([]Credential, error)
}

// Scope is the tenant scope for vault operations (mirrors iam.TenantScope to
// keep the vault context independent of IAM).
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}
