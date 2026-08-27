// Package iam is the Identity & Access Management bounded context. It holds pure
// domain types and the port interfaces the application layer depends on. It
// imports no framework, database, or transport code (Clean Architecture: the
// domain is the innermost layer).
package iam

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---- Identifiers ----

// ID is a domain identifier (UUID) shared by all IAM aggregates.
type ID = uuid.UUID

// NewID returns a fresh random identifier.
func NewID() ID { return uuid.New() }

// ---- Value objects ----

// Email is a normalized (lower-cased, trimmed) email address.
type Email string

// NewEmail normalizes and returns an Email. Validation of format is performed at
// the delivery boundary; here we only guarantee canonical form.
func NewEmail(raw string) Email {
	return Email(strings.ToLower(strings.TrimSpace(raw)))
}

func (e Email) String() string { return string(e) }

// AuthProvider identifies how a user authenticates.
type AuthProvider string

const (
	ProviderLocal AuthProvider = "local"
	ProviderLDAP  AuthProvider = "ldap"
	ProviderOIDC  AuthProvider = "oidc"
	ProviderSAML  AuthProvider = "saml"
	// ProviderSIEM is an account whose sign-in is vouched for by the SIEM's
	// exchange token. Distinct from ProviderOIDC even though both are federated:
	// the SIEM is not an OIDC provider to GuardRail, the linking key is different
	// (SSOIdentity.Subject rather than external_id), and telling them apart is
	// what lets "change your password there" name the right there.
	ProviderSIEM AuthProvider = "siem"
)

// ---- Aggregates ----

// Organization is a tenant. All other IAM aggregates (except system roles) are
// scoped to exactly one organization.
type Organization struct {
	ID        ID
	Name      string
	Slug      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// User is a principal within an organization.
type User struct {
	ID               ID
	OrganizationID   ID
	Email            Email
	Username         string
	PasswordHash     string // Argon2id encoded string; empty for federated users
	AuthProvider     AuthProvider
	Status           string // active | disabled | invited
	IsSuperAdmin     bool
	FailedLoginCount int
	LockedUntil      *time.Time
	LastLoginAt      *time.Time
	Roles            []Role // populated on load where needed
	// MustChangePassword marks a credential its owner did not choose — an
	// admin-set temporary password. The console forces a change at first sign-in.
	MustChangePassword bool
	// SSO links this account to the SIEM's idea of the same person, and records
	// whether its roles track the SIEM or a local administrator. Zero-valued on
	// every account that has never signed in through the SIEM, which is most of
	// them. See SSOIdentity.
	SSO       SSOIdentity
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsActive reports whether the user may authenticate right now.
func (u *User) IsActive(now time.Time) bool {
	if u.Status != "active" {
		return false
	}
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return false
	}
	return true
}

// IsLocked reports whether the account is currently locked out.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// Permissions flattens the permission keys granted through the user's roles.
func (u *User) Permissions() []string {
	seen := make(map[string]struct{})
	// Non-nil so a user with no roles serializes as [] rather than null: clients
	// treat this as a list, and null is a crash rather than "no permissions".
	out := []string{}
	for _, r := range u.Roles {
		for _, p := range r.Permissions {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}

// IsBootstrapAdmin reports whether this is the account the platform was
// installed with — the one seed-admin creates from GUARDRAIL_ADMIN_EMAIL on
// first boot.
//
// It is identified by the is_super_admin COLUMN specifically, not by
// HasSuperAdmin: the column is set only by that bootstrap, while the Super Admin
// ROLE is what the console hands out. So this distinguishes "the account that
// exists because the platform exists" from "somebody an administrator promoted",
// and only the first is protected.
//
// Its roles and password are protected because it is the recovery path. Every
// other privileged account can be recreated by it; nothing can recreate it
// except shell access to the server. An administrator who demotes it or resets
// its password — by accident, or because somebody talked them into it — is left
// with an account that still exists and still cannot administer anything, and no
// amount of remaining permission puts it back.
//
// Deletion is NOT refused. A removed account frees its email address (the
// uniqueness index is partial on deleted_at), so `guardrail seed-admin` puts it
// back on the server; that is a trip to the console-less side of the box, not a
// dead end. See app/iam.DeleteUser.
func (u *User) IsBootstrapAdmin() bool { return u.IsSuperAdmin }

// ApprovalLevel is the user's rank: the highest of their roles'.
func (u *User) ApprovalLevel() int { return EffectiveApprovalLevel(u.Roles) }

// RoleNames returns the names of the user's roles.
func (u *User) RoleNames() []string {
	out := make([]string, 0, len(u.Roles))
	for _, r := range u.Roles {
		out = append(out, r.Name)
	}
	return out
}

// SuperAdminRoleID is the seeded "Super Admin" system role (see db/seed.sql).
//
// It lives in the domain because holding it is what MAKES a principal a super
// admin — see HasSuperAdmin. The role carries no permission rows of its own, and
// deliberately so: super admin is "everything, including permissions that do not
// exist yet", which no static grant list can express.
var SuperAdminRoleID = ID(uuid.MustParse("10000000-0000-0000-0000-000000000001"))

// HasSuperAdmin reports whether the user has unrestricted access.
//
// Two things confer it: the is_super_admin column, which bootstraps the first
// admin from the environment before any role exists to assign, and holding the
// Super Admin role, which is the only route available through the console.
//
// Both are needed. Reading only the column made the console lie: assigning the
// role named "Super Admin" granted a role with zero permissions and left the
// column false, so the new super admin signed in to an empty dashboard and no
// access at all — the role was a label with nothing behind it.
func (u *User) HasSuperAdmin() bool {
	if u.IsSuperAdmin {
		return true
	}
	for _, r := range u.Roles {
		if r.ID == SuperAdminRoleID {
			return true
		}
	}
	return false
}

// Role is a named bundle of permissions. A system role has OrganizationID == nil
// and is shared across tenants as a template.
type Role struct {
	ID             ID
	OrganizationID *ID
	Name           string
	Description    string
	IsSystem       bool
	Permissions    []string    // permission keys, e.g. "device:connect"
	DeviceScope    DeviceScope // 'all' or 'scoped' — resource-level device reach
	// ApprovalLevel ranks this role for the approval gate. An approver must
	// outrank the requester STRICTLY, which is also what makes self-approval
	// impossible without a separate rule: your own level is never greater than
	// itself, and neither is a peer's.
	ApprovalLevel int
}

// EffectiveApprovalLevel is a person's rank: the highest of their roles'.
//
// MAX rather than sum or minimum, matching how device scope already unions
// across roles — one rule for "what do this person's roles add up to". Taking
// the minimum would let an administrator be demoted by also holding Read-only,
// which is how a rank system stops meaning anything.
func EffectiveApprovalLevel(roles []Role) int {
	level := 0
	for i := range roles {
		if roles[i].ApprovalLevel > level {
			level = roles[i].ApprovalLevel
		}
	}
	return level
}

// SuperAdminLevel is the rank a super admin is treated as holding. Above every
// seeded role, so nobody can be configured into outranking them.
const SuperAdminLevel = 1000

// CanDecide reports whether an approver may decide a request made at
// requesterLevel.
//
// Strictly greater, deliberately. Equal ranks approving each other is not a
// hierarchy — it is two operators signing each other's work, which is the
// realistic failure here rather than literal self-approval.
func CanDecide(approverLevel, requesterLevel int, isSuperAdmin bool) bool {
	if isSuperAdmin {
		return true
	}
	return approverLevel > requesterLevel
}

// Permission is a single granular capability in the catalogue.
type Permission struct {
	ID          ID
	Key         string
	Description string
}

// DeviceScope controls which devices a role's device:connect permission reaches.
type DeviceScope string

const (
	// DeviceScopeAll grants access to every device in the organization (the
	// backward-compatible default).
	DeviceScopeAll DeviceScope = "all"
	// DeviceScopeScoped restricts access to the role's granted device types and
	// asset groups (the union of the two).
	DeviceScopeScoped DeviceScope = "scoped"
)

// RoleDeviceAccess is a role's resource-level device entitlement: whether it
// reaches all devices or only an explicit set of device types and asset groups.
type RoleDeviceAccess struct {
	Scope       DeviceScope
	DeviceTypes []string
	GroupIDs    []ID
}

// AuthSession is one entry in a refresh-token family used for rotation and
// reuse detection. The raw token is never stored — only its hash.
type AuthSession struct {
	ID               ID
	UserID           ID
	FamilyID         ID
	RefreshTokenHash []byte
	UserAgent        string
	IP               string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
	// SSO marks a family opened by a SIEM exchange rather than by a password.
	// It is persisted rather than derived because a refresh rebuilds the access
	// token from the user record: without it here the marker would evaporate at
	// the first rotation, which is fifteen minutes into the session.
	SSO bool
}

// IsUsable reports whether the session can still mint a new access token.
func (s *AuthSession) IsUsable(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// AuthSessionView is a read model of one live login session. Because refresh
// tokens rotate — each refresh revokes the presented row and mints a new one in
// the same family — a single logical sign-in is a FamilyID, not a row. This view
// collapses a family to what an operator needs to see: who is signed in, from
// where, when they signed in (the family's first token) and when they were last
// active (its most recent token). Enriched with the owner's email for admin
// listings.
type AuthSessionView struct {
	FamilyID   ID
	UserID     ID
	Email      string
	IP         string
	UserAgent  string
	SignedInAt time.Time // family's first token issue = original sign-in
	LastSeenAt time.Time // current token issue = last activity (advances on refresh)
	ExpiresAt  time.Time
}

// SessionQuery filters the active-session listing. A nil pointer means "do not
// filter on this field"; the two are combined with AND.
type SessionQuery struct {
	UserID *ID // limit to one user (self view)
	OrgID  *ID // limit to one organization (admin view, scoped to a tenant)
}
