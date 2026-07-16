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
	CreatedAt          time.Time
	UpdatedAt          time.Time
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
