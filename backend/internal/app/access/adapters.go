package access

import (
	"context"
	"errors"

	"github.com/google/uuid"

	appvault "github.com/guardrail/guardrail/internal/app/vault"
	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/iam"
	vaultdom "github.com/guardrail/guardrail/internal/domain/vault"
)

// DeviceLookupAdapter adapts the assets device repository to the access
// context's DeviceLookup port, translating between the two bounded contexts.
type DeviceLookupAdapter struct {
	devices assets.DeviceRepository
}

// NewDeviceLookup constructs a DeviceLookupAdapter.
func NewDeviceLookup(devices assets.DeviceRepository) *DeviceLookupAdapter {
	return &DeviceLookupAdapter{devices: devices}
}

// Endpoint resolves a device to a connectable endpoint.
func (a *DeviceLookupAdapter) Endpoint(ctx context.Context, s access.Scope, deviceID uuid.UUID) (access.Endpoint, error) {
	d, err := a.devices.GetByID(ctx, assets.Scope{OrganizationID: s.OrganizationID, IsSuperAdmin: s.IsSuperAdmin}, deviceID)
	if err != nil {
		if errors.Is(err, assets.ErrNotFound) {
			return access.Endpoint{}, access.ErrNotFound
		}
		return access.Endpoint{}, err
	}
	// The device's scheme IS its protocol, and it is trusted only after parsing.
	// The previous derivation assumed "anything that isn't http is https", which
	// would hand an ssh device to the reverse proxy — and that proxy injects the
	// vaulted credential as an Authorization header, so the device password would
	// go to port 22 in the clear. An unrecognised protocol must stop the connect,
	// not pick a default.
	proto, err := access.ParseProtocol(d.Scheme)
	if err != nil {
		return access.Endpoint{}, err
	}
	return access.Endpoint{
		Protocol: proto, BaseURL: d.BaseURL(), Host: d.Host, Port: d.Port,
		VerifyTLS: d.VerifyTLS, CustomHeaders: d.CustomHeaders,
		Name: d.Name, DeviceType: d.DeviceType,
		AllowUnmanaged: d.AllowUnmanaged, RecordSessions: d.RecordSessions,
		RequiresApproval: d.RequiresApproval, MinApprovals: d.EffectiveMinApprovals(),
		CreatedBy: d.CreatedBy,
		// Resolved here rather than in the gateway: what a device captures is a
		// policy question about the device, and the gateway's job is to obey it.
		RecordingKinds: d.EffectiveRecordingKinds(),
		// A recorded web device still isolates even if its stored mode says
		// otherwise: a row that predates delivery_mode, or one written by something
		// that skipped the CHECK, must never be served by the proxy while its policy
		// promises evidence the proxy cannot produce. Belt and braces over the
		// database constraint.
		//
		// Scoped to web schemes because recording does not imply isolation anywhere
		// else: SSH is recorded by its own gateway keeping the transcript, and
		// claiming isolation for it would route a terminal session at a browser.
		Isolate: d.DeliveryMode == assets.DeliveryIsolated ||
			(d.RecordSessions && assets.IsWebScheme(d.Scheme)),
		IdleTimeoutMinutes: d.IdleTimeoutMinutes,
	}, nil
}

// VaultCredentialResolver adapts the vault service to the access context's
// CredentialResolver port. Resolution is just-in-time and audited as credential
// use by the vault service.
type VaultCredentialResolver struct {
	vault *appvault.Service
}

// NewCredentialResolver constructs a VaultCredentialResolver.
func NewCredentialResolver(v *appvault.Service) *VaultCredentialResolver {
	return &VaultCredentialResolver{vault: v}
}

// Resolve returns the plaintext credential for a session's device.
func (r *VaultCredentialResolver) Resolve(ctx context.Context, s *access.Session) (access.Credential, error) {
	claims := iam.Claims{UserID: s.UserID, OrganizationID: s.OrganizationID}
	rc, err := r.vault.ResolveForDevice(ctx, claims, s.DeviceID, &s.ID)
	if err != nil {
		// A device with no bound credential is a valid state: signal it so the
		// gateway can still open the session and show the device's login page.
		if errors.Is(err, vaultdom.ErrNotFound) {
			return access.Credential{}, access.ErrNoCredential
		}
		return access.Credential{}, err
	}
	return access.Credential{Username: rc.Username, Secret: rc.Secret, Injection: string(rc.Injection)}, nil
}

// CredentialInherited reports whether this user's credential on the device comes
// from an asset group rather than from the device itself.
//
// A missing credential is not inherited: the caller uses this to decide whether
// a device's owner may skip its approval gate, and "there is nothing to inject"
// is not a reason to make them ask permission.
func (r *VaultCredentialResolver) CredentialInherited(ctx context.Context, s access.Scope, deviceID, userID uuid.UUID) (bool, error) {
	claims := iam.Claims{OrganizationID: s.OrganizationID, IsSuperAdmin: s.IsSuperAdmin, UserID: userID}
	inherited, err := r.vault.CredentialInherited(ctx, claims, deviceID)
	if errors.Is(err, vaultdom.ErrNotFound) {
		return false, nil
	}
	return inherited, err
}

// HasCredential reports whether this user would be injected with a credential on
// the device, without decrypting or auditing. Used by the broker as a
// fail-closed pre-flight.
//
// The claims carry UserID because the answer is per person on a per-user device.
// They deliberately do NOT carry IsSuperAdmin's connect privileges into the
// credential question: being able to reach every device is not the same as
// having an account on one.
func (r *VaultCredentialResolver) HasCredential(ctx context.Context, s access.Scope, deviceID, userID uuid.UUID) (bool, error) {
	claims := iam.Claims{OrganizationID: s.OrganizationID, IsSuperAdmin: s.IsSuperAdmin, UserID: userID}
	return r.vault.HasCredential(ctx, claims, deviceID)
}

// RoleRanker adapts the IAM role repository to the access context's Ranker port,
// so the broker can ask "who outranks this person" without importing IAM's
// application layer.
type RoleRanker struct {
	roles iam.RoleRepository
}

// NewRoleRanker constructs a RoleRanker.
func NewRoleRanker(roles iam.RoleRepository) *RoleRanker { return &RoleRanker{roles: roles} }

// LevelFor returns a user's effective rank: the highest of their roles'.
func (r *RoleRanker) LevelFor(ctx context.Context, s access.Scope, userID uuid.UUID) (int, error) {
	return r.roles.MaxApprovalLevel(ctx, tenantScope(s), userID)
}

// ApproversAbove counts active users who hold approval:decide and outrank the
// given level.
func (r *RoleRanker) ApproversAbove(ctx context.Context, s access.Scope, level int) (int, error) {
	return r.roles.ApproverCountAbove(ctx, tenantScope(s), level)
}

func tenantScope(s access.Scope) iam.TenantScope {
	return iam.TenantScope{OrganizationID: s.OrganizationID, IsSuperAdmin: s.IsSuperAdmin}
}
