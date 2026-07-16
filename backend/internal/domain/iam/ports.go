package iam

import (
	"context"
	"time"
)

// TenantScope carries the tenant context that infrastructure uses to enforce
// Row-Level Security (SET LOCAL app.current_org / app.is_super_admin) and that
// the application uses for authorization decisions.
type TenantScope struct {
	OrganizationID ID
	IsSuperAdmin   bool
}

// UserRepository persists and retrieves users. All methods are tenant-scoped
// except the *Global lookups used by the login flow (which must resolve a user
// before a tenant is known).
type UserRepository interface {
	Create(ctx context.Context, s TenantScope, u *User) error
	Update(ctx context.Context, s TenantScope, u *User) error
	GetByID(ctx context.Context, s TenantScope, id ID) (*User, error)
	List(ctx context.Context, s TenantScope, page Page) ([]User, error)
	SoftDelete(ctx context.Context, s TenantScope, id ID) error

	// GetByEmailGlobal resolves candidate users by email across all tenants,
	// used during login before an organization is established. Returns matching
	// active users with roles loaded.
	GetByEmailGlobal(ctx context.Context, email Email) ([]User, error)
	// GetByEmailInOrg resolves a single user within a known organization.
	GetByEmailInOrg(ctx context.Context, orgID ID, email Email) (*User, error)

	// SetRoles replaces the user's role assignments.
	SetRoles(ctx context.Context, s TenantScope, userID ID, roleIDs []ID) error
	// RecordLoginSuccess resets failure counters and stamps last_login_at.
	RecordLoginSuccess(ctx context.Context, userID ID, at time.Time) error
	// RecordLoginFailure increments the failure counter and optionally locks.
	RecordLoginFailure(ctx context.Context, userID ID, lockUntil *time.Time) error
	// UpdatePasswordHash sets a new password hash (used for rehash-on-login and
	// password changes).
	UpdatePasswordHash(ctx context.Context, userID ID, hash string) error
	// SetMustChangePassword raises or clears the forced-password-change flag.
	SetMustChangePassword(ctx context.Context, userID ID, must bool) error
}

// RefreshTokenGenerator creates opaque refresh tokens and hashes them for
// storage. The raw token is returned to the client once; only the hash persists.
type RefreshTokenGenerator interface {
	Generate() (raw string, hash []byte, err error)
	Hash(raw string) []byte
}

// OrganizationRepository persists organizations. Creation and listing across
// tenants require super-admin scope.
type OrganizationRepository interface {
	Create(ctx context.Context, s TenantScope, o *Organization) error
	Update(ctx context.Context, s TenantScope, o *Organization) error
	GetByID(ctx context.Context, s TenantScope, id ID) (*Organization, error)
	GetBySlug(ctx context.Context, slug string) (*Organization, error)
	List(ctx context.Context, s TenantScope, page Page) ([]Organization, error)
}

// RoleRepository reads roles and the permission catalogue.
type RoleRepository interface {
	List(ctx context.Context, s TenantScope, page Page) ([]Role, error)
	GetByID(ctx context.Context, s TenantScope, id ID) (*Role, error)
	Create(ctx context.Context, s TenantScope, r *Role) error
	SetPermissions(ctx context.Context, s TenantScope, roleID ID, permissionKeys []string) error
	ListPermissions(ctx context.Context) ([]Permission, error)
	// GetDeviceAccess returns a role's resource-level device entitlement.
	GetDeviceAccess(ctx context.Context, s TenantScope, roleID ID) (*RoleDeviceAccess, error)
	// SetDeviceAccess replaces a role's device scope and its granted device types
	// and asset groups.
	SetDeviceAccess(ctx context.Context, s TenantScope, roleID ID, access RoleDeviceAccess) error
}

// AuthSessionRepository manages refresh-token families.
type AuthSessionRepository interface {
	Create(ctx context.Context, sess *AuthSession) error
	GetByTokenHash(ctx context.Context, hash []byte) (*AuthSession, error)
	Revoke(ctx context.Context, id ID, at time.Time) error
	RevokeFamily(ctx context.Context, familyID ID, at time.Time) error
	RevokeAllForUser(ctx context.Context, userID ID, at time.Time) error

	// ListActive returns one view per live login session (family) matching the
	// query, most-recently-active first.
	ListActive(ctx context.Context, q SessionQuery) ([]AuthSessionView, error)
	// FamilyOwner resolves the user and organization that own a session family,
	// used to authorize a revoke. Returns ErrNotFound if the family is unknown.
	FamilyOwner(ctx context.Context, familyID ID) (userID ID, orgID ID, err error)
}

// Page is a simple cursor/limit pagination request.
type Page struct {
	Limit  int
	Cursor string
}

// ---- Security ports (implemented in infra/security) ----

// PasswordHasher hashes and verifies passwords. The implementation is Argon2id.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
	// NeedsRehash reports whether an existing hash uses outdated parameters and
	// should be transparently upgraded on next successful login.
	NeedsRehash(encodedHash string) bool
}

// Claims is the authenticated principal encoded in an access token.
type Claims struct {
	UserID         ID
	OrganizationID ID
	Email          string
	IsSuperAdmin   bool
	Roles          []string
	Permissions    []string
}

// Scope derives the tenant scope for repository/authorization use.
func (c Claims) Scope() TenantScope {
	return TenantScope{OrganizationID: c.OrganizationID, IsSuperAdmin: c.IsSuperAdmin}
}

// Has reports whether the principal holds a permission (super admin holds all).
func (c Claims) Has(permission string) bool {
	if c.IsSuperAdmin {
		return true
	}
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// TokenIssuer signs and verifies short-lived access tokens (JWT).
type TokenIssuer interface {
	Issue(c Claims, now time.Time) (token string, expiresAt time.Time, err error)
	Verify(token string) (Claims, error)
}

// Clock abstracts time for deterministic testing.
type Clock interface{ Now() time.Time }

// SystemClock is the production Clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }
