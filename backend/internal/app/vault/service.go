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
	"time"

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
	// PerUser and Inherited describe where this credential came from, so the
	// console can tell somebody they will connect as their own named account
	// rather than the device's shared login — before they press Connect.
	PerUser   bool
	Inherited bool
	// RotatedAt is when the secret last changed; nil means never since creation.
	RotatedAt *time.Time
	// AgeDays is how long the secret has gone unchanged, measured from the
	// rotation if there was one and from creation otherwise.
	AgeDays int
}

// BindingView is one per-user account binding, for the console listing.
type BindingView struct {
	CredentialID uuid.UUID
	Name         string
	Username     string
	Injection    vault.InjectionMethod
	UserID       *uuid.UUID
	UserEmail    string
	DeviceID     *uuid.UUID
	GroupID      *uuid.UUID
	GroupName    string
	RotatedAt    *time.Time
	AgeDays      int
}

// ResolvedCredential is the plaintext form handed to the gateway for injection.
type ResolvedCredential struct {
	Username  string
	Secret    string
	Injection vault.InjectionMethod
	// PerUser and Inherited are provenance, carried so the broker can apply the
	// owner-bypass limit: a device's owner skips the approval gate on their own
	// device, but not when the credential was inherited from a group they never
	// supplied it to.
	PerUser   bool
	Inherited bool
}

func scopeOf(a iam.Claims) vault.Scope {
	return vault.Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

func view(c *vault.Credential) CredentialView {
	return CredentialView{
		ID: c.ID, Name: c.Name, Type: c.Type, Username: c.Username,
		Injection: c.Injection, KEKID: c.Sealed.KEKID, HasSecret: len(c.Sealed.Ciphertext) > 0,
		RotatedAt: c.RotatedAt, AgeDays: secretAgeDays(c.RotatedAt, c.CreatedAt),
	}
}

// secretAgeDays is how long a secret has gone unchanged.
//
// Measured from creation when it has never been rotated, rather than reported as
// unknown: "never rotated" and "rotated three years ago" are the same exposure,
// and calling the first one unknown would hide the oldest secrets in the vault
// from the very surface built to find them.
func secretAgeDays(rotated *time.Time, created time.Time) int {
	from := created
	if rotated != nil {
		from = *rotated
	}
	if from.IsZero() {
		return 0
	}
	d := int(time.Since(from).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func bindingView(b *vault.Binding) BindingView {
	return BindingView{
		CredentialID: b.CredentialID, Name: b.CredentialName, Username: b.Username,
		Injection: b.Injection, UserID: b.UserID, UserEmail: b.UserEmail,
		DeviceID: b.DeviceID, GroupID: b.GroupID, GroupName: b.GroupName,
		RotatedAt: b.RotatedAt, AgeDays: secretAgeDays(b.RotatedAt, b.CreatedAt),
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

// BindToDevice binds a credential to a device. A nil userID makes it the shared
// credential; a non-nil one makes it that person's named account.
func (s *Service) BindToDevice(ctx context.Context, actor iam.Claims, deviceID, credentialID uuid.UUID, userID *uuid.UUID) error {
	return s.repo.BindToDevice(ctx, scopeOf(actor), deviceID, credentialID, userID)
}

// GetForDevice returns the metadata of the credential this actor would be
// injected with on a device (never the secret), or (nil, nil) if they would get
// none. It never decrypts and never audits, so it is safe for read projections.
func (s *Service) GetForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (*CredentialView, error) {
	res, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID, actor.UserID)
	if errors.Is(err, vault.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v := view(res.Credential)
	v.PerUser, v.Inherited = res.PerUser, res.Inherited
	return &v, nil
}

// SetForDevice makes `in` the single credential a device owns: it rotates the
// device's existing credential in place if one exists, otherwise it seals a new
// credential and binds it as the device default. On update, an empty Secret
// preserves the current secret (the console never echoes it back), while the
// username and injection are always applied. Creating a new credential requires
// a secret.
func (s *Service) SetForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, in CredentialInput) error {
	return s.setBinding(ctx, actor, deviceID, nil, nil, in)
}

// SetForUser binds a person's own named account on a device (or, with a group
// id, across that group's subtree). This is the per-user path: the credential is
// an account that exists ON THE DEVICE, such as `jsmith-admin` — never the
// person's own login password, which GuardRail must not hold.
func (s *Service) SetForUser(ctx context.Context, actor iam.Claims, deviceID, groupID *uuid.UUID, userID uuid.UUID, in CredentialInput) error {
	if deviceID == nil && groupID == nil {
		return fmt.Errorf("%w: a per-user account must name a device or a group", vault.ErrInvalid)
	}
	if deviceID != nil {
		return s.setBinding(ctx, actor, *deviceID, nil, &userID, in)
	}
	return s.setBinding(ctx, actor, uuid.Nil, groupID, &userID, in)
}

// setBinding is the one write path for every kind of binding: shared on a
// device, one person's on a device, one person's on a group.
//
// It rotates in place when a binding already exists and creates one otherwise,
// so the console can send the same payload either way. An empty secret on update
// keeps the stored one (the console never echoes a secret back); creating
// requires a secret, because a credential that authenticates with nothing is a
// device that looks configured and refuses every connection.
func (s *Service) setBinding(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, groupID *uuid.UUID, userID *uuid.UUID, in CredentialInput) error {
	// Checked before anything is written, so a refused request changes nothing.
	if err := validateInjection(in); err != nil {
		return err
	}
	existing, err := s.existingBinding(ctx, actor, deviceID, groupID, userID)
	if err != nil {
		return err
	}
	if existing != nil {
		cred, gerr := s.repo.GetByID(ctx, scopeOf(actor), existing.CredentialID)
		if gerr != nil {
			return gerr
		}
		if in.Secret != "" {
			sealed, serr := s.enc.Seal([]byte(in.Secret))
			if serr != nil {
				return serr
			}
			cred.Sealed = sealed
		}
		if in.Name != "" {
			cred.Name = in.Name
		}
		cred.Username = in.Username
		cred.Injection = defaultInjection(in.Injection, in.Scheme)
		if uerr := s.repo.Update(ctx, scopeOf(actor), cred); uerr != nil {
			return uerr
		}
		s.record(ctx, actor, "credential.rotate", cred.ID, in.Meta, audit.ResultSuccess)
		return nil
	}

	if in.Secret == "" {
		return vault.ErrSecretRequired
	}
	if in.Name == "" {
		in.Name = "device credential"
		if userID != nil {
			in.Name = in.Username
			if in.Name == "" {
				in.Name = "per-user account"
			}
		}
	}
	v, cerr := s.Create(ctx, actor, in)
	if cerr != nil {
		return cerr
	}
	if groupID != nil {
		return s.repo.BindToGroup(ctx, scopeOf(actor), *groupID, v.ID, *userID)
	}
	return s.repo.BindToDevice(ctx, scopeOf(actor), deviceID, v.ID, userID)
}

// existingBinding finds the binding a write would replace, or nil.
func (s *Service) existingBinding(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, groupID, userID *uuid.UUID) (*vault.Binding, error) {
	var list []vault.Binding
	var err error
	if groupID != nil {
		list, err = s.repo.ListGroupBindings(ctx, scopeOf(actor), *groupID)
	} else {
		list, err = s.repo.ListDeviceBindings(ctx, scopeOf(actor), deviceID)
	}
	if err != nil {
		return nil, err
	}
	for i := range list {
		b := &list[i]
		switch {
		case userID == nil && b.UserID == nil:
			return b, nil
		case userID != nil && b.UserID != nil && *b.UserID == *userID:
			return b, nil
		}
	}
	return nil, nil
}

// ClearForDevice removes the credential a device owns (soft-delete), returning
// the device to the unmanaged state. It is a no-op if the device has none.
func (s *Service) ClearForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, meta ReqMeta) error {
	return s.clearBinding(ctx, actor, deviceID, nil, nil, meta)
}

// ClearForUser removes one person's named account from a device or a group.
func (s *Service) ClearForUser(ctx context.Context, actor iam.Claims, deviceID, groupID *uuid.UUID, userID uuid.UUID, meta ReqMeta) error {
	if deviceID != nil {
		return s.clearBinding(ctx, actor, *deviceID, nil, &userID, meta)
	}
	if groupID != nil {
		return s.clearBinding(ctx, actor, uuid.Nil, groupID, &userID, meta)
	}
	return fmt.Errorf("%w: a per-user account must name a device or a group", vault.ErrInvalid)
}

func (s *Service) clearBinding(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, groupID, userID *uuid.UUID, meta ReqMeta) error {
	existing, err := s.existingBinding(ctx, actor, deviceID, groupID, userID)
	if err != nil || existing == nil {
		return err
	}
	if groupID != nil {
		if uerr := s.repo.UnbindFromGroup(ctx, scopeOf(actor), *groupID, *userID); uerr != nil {
			return uerr
		}
	} else if uerr := s.repo.UnbindFromDevice(ctx, scopeOf(actor), deviceID, userID); uerr != nil {
		return uerr
	}
	if derr := s.repo.SoftDelete(ctx, scopeOf(actor), existing.CredentialID); derr != nil {
		return derr
	}
	s.record(ctx, actor, "credential.delete", existing.CredentialID, meta, audit.ResultSuccess)
	return nil
}

// DeviceBindings returns every account bound to a device, its own and the ones
// it inherits from asset groups above it.
func (s *Service) DeviceBindings(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (own, inherited []BindingView, err error) {
	ob, err := s.repo.ListDeviceBindings(ctx, scopeOf(actor), deviceID)
	if err != nil {
		return nil, nil, err
	}
	ib, err := s.repo.ListInheritedBindings(ctx, scopeOf(actor), deviceID)
	if err != nil {
		return nil, nil, err
	}
	own = make([]BindingView, 0, len(ob))
	for i := range ob {
		own = append(own, bindingView(&ob[i]))
	}
	inherited = make([]BindingView, 0, len(ib))
	for i := range ib {
		inherited = append(inherited, bindingView(&ib[i]))
	}
	return own, inherited, nil
}

// GroupBindings returns every per-user account bound to an asset group.
func (s *Service) GroupBindings(ctx context.Context, actor iam.Claims, groupID uuid.UUID) ([]BindingView, error) {
	list, err := s.repo.ListGroupBindings(ctx, scopeOf(actor), groupID)
	if err != nil {
		return nil, err
	}
	out := make([]BindingView, 0, len(list))
	for i := range list {
		out = append(out, bindingView(&list[i]))
	}
	return out, nil
}

// UserBindings returns every account belonging to one person.
func (s *Service) UserBindings(ctx context.Context, actor iam.Claims, userID uuid.UUID) ([]BindingView, error) {
	list, err := s.repo.ListUserBindings(ctx, scopeOf(actor), userID)
	if err != nil {
		return nil, err
	}
	out := make([]BindingView, 0, len(list))
	for i := range list {
		out = append(out, bindingView(&list[i]))
	}
	return out, nil
}

// RetireUserCredentials soft-deletes every credential belonging to a person,
// for offboarding. It returns how many were retired.
//
// Deliberately explicit rather than a database cascade: a deletion that quietly
// destroys vault material is its own incident, and the count is what the console
// reports back so somebody can see what just happened.
func (s *Service) RetireUserCredentials(ctx context.Context, actor iam.Claims, userID uuid.UUID, meta ReqMeta) (int, error) {
	ids, err := s.repo.CredentialIDsForUser(ctx, scopeOf(actor), userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if derr := s.repo.SoftDelete(ctx, scopeOf(actor), id); derr != nil {
			return n, derr
		}
		s.record(ctx, actor, "credential.delete", id, meta, audit.ResultSuccess)
		n++
	}
	return n, nil
}

// StaleCredentials returns credentials whose secret has gone unchanged for
// longer than olderThan.
func (s *Service) StaleCredentials(ctx context.Context, actor iam.Claims, olderThan time.Duration, limit int) ([]CredentialView, error) {
	list, err := s.repo.StaleCredentials(ctx, scopeOf(actor), time.Now().Add(-olderThan), limit)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialView, 0, len(list))
	for i := range list {
		out = append(out, view(&list[i]))
	}
	return out, nil
}

// CredentialInherited reports whether the credential this actor would be
// injected with on a device came from an asset group rather than from the device
// itself. It reads the sealed binding only — nothing is decrypted or audited.
func (s *Service) CredentialInherited(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (bool, error) {
	res, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID, actor.UserID)
	if err != nil {
		return false, err
	}
	return res.Inherited, nil
}

// HasCredential reports whether this actor would be injected with a credential
// on the device. It never decrypts and never audits, so it is safe as a
// fail-closed pre-flight before establishing a session.
//
// It asks the same question ResolveForDevice answers, for the same user. A
// pre-flight that checks "does this device have any credential" while the
// resolution checks "does this person have one here" would let a per-user
// device pass on somebody else's account and fail at injection time, after the
// session row exists.
func (s *Service) HasCredential(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) (bool, error) {
	return s.repo.HasCredentialForDevice(ctx, scopeOf(actor), deviceID, actor.UserID)
}

// DevicesWithCredential returns which of the given device IDs are provisioned —
// connectable by somebody — for annotating device listings.
//
// An estate view, not a personal one: "is this device set up" is a different
// question from "what do I connect as", and conflating them would show forty
// working per-user devices as unconfigured to an administrator who holds no
// account on any of them.
func (s *Service) DevicesWithCredential(ctx context.Context, actor iam.Claims, deviceIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	return s.repo.DeviceIDsProvisioned(ctx, scopeOf(actor), deviceIDs)
}

// ResolveForDevice returns the plaintext credential for just-in-time injection
// by the gateway. This is the ONLY path that decrypts a secret, and it is always
// audited as credential use. Callers must already be authorized to connect.
func (s *Service) ResolveForDevice(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, sessionID *uuid.UUID) (*ResolvedCredential, error) {
	res, err := s.repo.ResolveForDevice(ctx, scopeOf(actor), deviceID, actor.UserID)
	if err != nil {
		return nil, err
	}
	c := res.Credential
	plaintext, err := s.enc.Open(c.Sealed)
	if err != nil {
		return nil, err
	}
	org := actor.OrganizationID
	uid := actor.UserID
	if s.audit != nil {
		// The account name and the provenance go into the event, not just the
		// credential id. Correlating a GuardRail session with the target's own
		// logs is the entire payoff of per-user accounts, and the target logs
		// record a username — a UUID cannot be joined to anything over there.
		// Never the secret: this records which account, not how it authenticated.
		_ = s.audit.Record(ctx, audit.Event{
			ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
			Action: "credential.use", Category: audit.CategoryVault, TargetType: "credential",
			TargetID: c.ID.String(), SessionID: sessionID, Result: audit.ResultSuccess,
			Detail: map[string]any{
				"account":   c.Username,
				"per_user":  res.PerUser,
				"inherited": res.Inherited,
			},
		})
	}
	return &ResolvedCredential{
		Username: c.Username, Secret: string(plaintext), Injection: c.Injection,
		PerUser: res.PerUser, Inherited: res.Inherited,
	}, nil
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
