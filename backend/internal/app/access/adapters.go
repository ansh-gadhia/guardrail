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
		AllowUnmanaged: d.AllowUnmanaged, RecordSessions: d.RecordSessions,
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

// HasCredential reports whether a device has at least one bound credential,
// without decrypting or auditing. Used by the broker as a fail-closed pre-flight.
func (r *VaultCredentialResolver) HasCredential(ctx context.Context, s access.Scope, deviceID uuid.UUID) (bool, error) {
	claims := iam.Claims{OrganizationID: s.OrganizationID, IsSuperAdmin: s.IsSuperAdmin}
	return r.vault.HasCredential(ctx, claims, deviceID)
}
