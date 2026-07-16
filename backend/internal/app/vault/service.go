// Package vault is the application layer for the credential vault. It seals
// secrets on write, exposes only metadata on read, resolves plaintext solely for
// just-in-time injection by the gateway (audited as credential use), and rotates
// KEKs by re-wrapping DEKs.
package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/domain/vault"
)

// Service implements the credential-vault use cases.
type Service struct {
	repo  vault.CredentialRepository
	enc   vault.Encryptor
	audit audit.Recorder
}

// NewService constructs the vault service.
func NewService(repo vault.CredentialRepository, enc vault.Encryptor, rec audit.Recorder) *Service {
	return &Service{repo: repo, enc: enc, audit: rec}
}

// ReqMeta carries request metadata for auditing.
type ReqMeta struct{ IP, UserAgent string }

// CredentialInput describes a credential create/rotate. Secret is plaintext and
// is sealed immediately; it is never persisted or logged in the clear.
type CredentialInput struct {
	Name     string
	Type     vault.CredentialType
	Username string
	// Injection is how the secret reaches the device. Empty means "the default for
	// this device's protocol", which is why Scheme travels with it.
	Injection vault.InjectionMethod
	// Scheme is the protocol of the device this credential is for. It is here so
	// the injection method can be checked against something real: a credential is
	// only meaningful next to the device it authenticates, and "basic over ssh" is
	// only detectable when both are known. Empty skips the check, for callers that
	// genuinely have no device (there are none today).
	Scheme string
	Secret string
	Meta   ReqMeta
}

// CredentialView is the safe, read-only projection returned to clients — it
// never contains secret material.
type CredentialView struct {
	ID        uuid.UUID
	Name      string
	Type      vault.CredentialType
	Username  string
	Injection vault.InjectionMethod
	KEKID     string
	HasSecret bool
}

// ResolvedCredential is the plaintext form handed to the gateway for injection.
type ResolvedCredential struct {
	Username  string
	Secret    string
	Injection vault.InjectionMethod
}

func scopeOf(a iam.Claims) vault.Scope {
	return vault.Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

func view(c *vault.Credential) CredentialView {
	return CredentialView{
		ID: c.ID, Name: c.Name, Type: c.Type, Username: c.Username,
		Injection: c.Injection, KEKID: c.Sealed.KEKID, HasSecret: len(c.Sealed.Ciphertext) > 0,
	}
}

// Create seals and stores a new credential.
func (s *Service) Create(ctx context.Context, actor iam.Claims, in CredentialInput) (*CredentialView, error) {
	if err := validateInjection(in); err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal([]byte(in.Secret))
	if err != nil {
		return nil, err
	}
	c := &vault.Credential{
		ID: uuid.New(), OrganizationID: actor.OrganizationID, Name: in.Name,
		Type: defaultType(in.Type), Username: in.Username, Injection: defaultInjection(in.Injection, in.Scheme),
		Sealed: sealed,
	}
	if err := s.repo.Create(ctx, scopeOf(actor), c); err != nil {
		return nil, err
	}
	s.record(ctx, actor, "credential.create", c.ID, in.Meta, audit.ResultSuccess)
	v := view(c)
	return &v, nil
}

// Get returns credential metadata (never the secret).
func (s *Service) Get(ctx context.Context, actor iam.Claims, id uuid.UUID) (*CredentialView, error) {
	c, err := s.repo.GetByID(ctx, scopeOf(actor), id)
	if err != nil {
		return nil, err
	}
	v := view(c)
	return &v, nil
}

// List returns credential metadata for the tenant.
func (s *Service) List(ctx context.Context, actor iam.Claims, limit int) ([]CredentialView, error) {
	creds, err := s.repo.List(ctx, scopeOf(actor), limit)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialView, 0, len(creds))
	for i := range creds {
		out = append(out, view(&creds[i]))
	}
	return out, nil
}

// Rotate replaces the secret material of an existing credential.
func (s *Service) Rotate(ctx context.Context, actor iam.Claims, id uuid.UUID, in CredentialInput) (*CredentialView, error) {
	c, err := s.repo.GetByID(ctx, scopeOf(actor), id)
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal([]byte(in.Secret))
	if err != nil {
		return nil, err
	}
	c.Sealed = sealed
	if in.Name != "" {
		c.Name = in.Name
	}
	if in.Username != "" {
		c.Username = in.Username
	}
	if in.Injection != "" {
		c.Injection = in.Injection
	}
	if err := s.repo.Update(ctx, scopeOf(actor), c); err != nil {
		return nil, err
	}
	s.record(ctx, actor, "credential.rotate", c.ID, in.Meta, audit.ResultSuccess)
	v := view(c)
	return &v, nil
}

// Delete soft-deletes a credential.
func (s *Service) Delete(ctx context.Context, actor iam.Claims, id uuid.UUID, meta ReqMeta) error {
	if err := s.repo.SoftDelete(ctx, scopeOf(actor), id); err != nil {
		return err
	}
	s.record(ctx, actor, "credential.delete", id, meta, audit.ResultSuccess)
	return nil
}

// BindToDevice binds a credential to a device.
func (s *Service) BindToDevice(ctx context.Context, actor iam.Claims, deviceID, credentialID uuid.UUID, isDefault bool) error {
	return s.repo.BindToDevice(ctx, scopeOf(actor), deviceID, credentialID, isDefault)
}

// GetForDevice returns the metadata of the credential a device owns (never the
// secret), or (nil, nil) if the device has none. It never decrypts and never
// audits, so it is safe for read projections. A device owns at most one
// credential in the console model.
func (s *Service) GetForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (*CredentialView, error) {
	c, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID)
	if errors.Is(err, vault.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v := view(c)
	return &v, nil
}

// SetForDevice makes `in` the single credential a device owns: it rotates the
// device's existing credential in place if one exists, otherwise it seals a new
// credential and binds it as the device default. On update, an empty Secret
// preserves the current secret (the console never echoes it back), while the
// username and injection are always applied. Creating a new credential requires
// a secret.
func (s *Service) SetForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, in CredentialInput) error {
	// Checked before anything is written, so a refused request changes nothing.
	if err := validateInjection(in); err != nil {
		return err
	}
	existing, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID)
	switch {
	case err == nil:
		// Update the owned credential in place.
		if in.Secret != "" {
			sealed, serr := s.enc.Seal([]byte(in.Secret))
			if serr != nil {
				return serr
			}
			existing.Sealed = sealed
		}
		if in.Name != "" {
			existing.Name = in.Name
		}
		existing.Username = in.Username
		existing.Injection = defaultInjection(in.Injection, in.Scheme)
		if uerr := s.repo.Update(ctx, scopeOf(actor), existing); uerr != nil {
			return uerr
		}
		s.record(ctx, actor, "credential.rotate", existing.ID, in.Meta, audit.ResultSuccess)
		return nil
	case errors.Is(err, vault.ErrNotFound):
		// No credential yet — create and bind one. A secret is mandatory here.
		if in.Secret == "" {
			return vault.ErrSecretRequired
		}
		if in.Name == "" {
			in.Name = "device credential"
		}
		v, cerr := s.Create(ctx, actor, in)
		if cerr != nil {
			return cerr
		}
		return s.repo.BindToDevice(ctx, scopeOf(actor), deviceID, v.ID, true)
	default:
		return err
	}
}

// ClearForDevice removes the credential a device owns (soft-delete), returning
// the device to the unmanaged state. It is a no-op if the device has none.
func (s *Service) ClearForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, meta ReqMeta) error {
	existing, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID)
	if errors.Is(err, vault.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if derr := s.repo.SoftDelete(ctx, scopeOf(actor), existing.ID); derr != nil {
		return derr
	}
	s.record(ctx, actor, "credential.delete", existing.ID, meta, audit.ResultSuccess)
	return nil
}

// HasCredential reports whether a device has at least one bound credential. It
// never decrypts and never audits, so it is safe as a fail-closed pre-flight
// before establishing a session.
func (s *Service) HasCredential(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (bool, error) {
	return s.repo.HasCredentialForDevice(ctx, scopeOf(actor), deviceID)
}

// DevicesWithCredential returns which of the given device IDs currently have a
// bound credential, for annotating device listings.
func (s *Service) DevicesWithCredential(ctx context.Context, actor iam.Claims, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	return s.repo.DeviceIDsWithCredential(ctx, scopeOf(actor), deviceIDs)
}

// ResolveForDevice returns the plaintext credential for just-in-time injection
// by the gateway. This is the ONLY path that decrypts a secret, and it is always
// audited as credential use. Callers must already be authorized to connect.
func (s *Service) ResolveForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, sessionID *uuid.UUID) (*ResolvedCredential, error) {
	c, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.enc.Open(c.Sealed)
	if err != nil {
		return nil, err
	}
	org := actor.OrganizationID
	uid := actor.UserID
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Event{
			ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
			Action: "credential.use", Category: audit.CategoryVault, TargetType: "credential",
			TargetID: c.ID.String(), SessionID: sessionID, Result: audit.ResultSuccess,
		})
	}
	return &ResolvedCredential{Username: c.Username, Secret: string(plaintext), Injection: c.Injection}, nil
}

// RotateKEK re-wraps all credentials currently under oldKEKID onto the active
// KEK, in batches. Secret ciphertext is untouched. Returns the count rotated.
func (s *Service) RotateKEK(ctx context.Context, oldKEKID string, batch int) (int, error) {
	if batch <= 0 {
		batch = 100
	}
	rotated := 0
	for {
		creds, err := s.repo.ListByKEK(ctx, oldKEKID, batch)
		if err != nil {
			return rotated, err
		}
		if len(creds) == 0 {
			return rotated, nil
		}
		for i := range creds {
			c := &creds[i]
			resealed, err := s.enc.Rewrap(c.Sealed)
			if err != nil {
				return rotated, err
			}
			c.Sealed = resealed
			scope := vault.Scope{OrganizationID: c.OrganizationID, IsSuperAdmin: true}
			if err := s.repo.Update(ctx, scope, c); err != nil {
				return rotated, err
			}
			rotated++
		}
		if len(creds) < batch {
			return rotated, nil
		}
	}
}

func (s *Service) record(ctx context.Context, actor iam.Claims, action string, id uuid.UUID, meta ReqMeta, result audit.Result) {
	if s.audit == nil {
		return
	}
	org := actor.OrganizationID
	uid := actor.UserID
	_ = s.audit.Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
		Action: action, Category: audit.CategoryVault, TargetType: "credential", TargetID: id.String(),
		IP: meta.IP, UserAgent: meta.UserAgent, Result: result,
	})
}

func defaultType(t vault.CredentialType) vault.CredentialType {
	if t == "" {
		return vault.TypePassword
	}
	return t
}

// defaultInjection resolves the method when the caller named none.
//
// It used to default to `form` regardless — which is a web login form, and was
// therefore the wrong answer for every device that is not a web UI.
func defaultInjection(m vault.InjectionMethod, scheme string) vault.InjectionMethod {
	if m != "" {
		return m
	}
	if scheme != "" {
		return vault.DefaultInjectionFor(scheme)
	}
	return vault.InjectForm
}

// validateInjection refuses a credential that could not authenticate its device.
//
// The message names the protocol and the methods that would work, because the
// operator's next question is always "then what should I have picked?" — and
// "invalid input" does not answer it.
func validateInjection(in CredentialInput) error {
	if in.Scheme == "" || in.Injection == "" {
		return nil
	}
	if vault.InjectionValidFor(in.Injection, in.Scheme) {
		return nil
	}
	return fmt.Errorf("%w: %q cannot authenticate a %s device (use %s)",
		vault.ErrInjectionMismatch, in.Injection, in.Scheme, joinMethods(vault.InjectionsFor(in.Scheme)))
}

func joinMethods(ms []vault.InjectionMethod) string {
	if len(ms) == 0 {
		return "none — this protocol takes no credential"
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m))
	}
	return strings.Join(out, " or ")
}
