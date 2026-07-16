package iam

import (
	"context"
	"sync"
	"time"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// fakeUserRepo is an in-memory iam.UserRepository for use-case tests.
type fakeUserRepo struct {
	mu    sync.Mutex
	users map[iam.ID]*iam.User
	// roleGrants records every SetRoles call. A no-op SetRoles cannot tell
	// "the grant was refused" from "the grant went through and did nothing",
	// which is the entire question for a privilege check.
	roleGrants map[iam.ID][]iam.ID
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: map[iam.ID]*iam.User{}, roleGrants: map[iam.ID][]iam.ID{}}
}

// rolesOf returns the roles last granted to a user, and whether SetRoles ran.
func (f *fakeUserRepo) rolesOf(id iam.ID) ([]iam.ID, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.roleGrants[id]
	return r, ok
}

func (f *fakeUserRepo) add(u *iam.User) { f.users[u.ID] = u }

func (f *fakeUserRepo) clone(u *iam.User) *iam.User {
	cp := *u
	return &cp
}

func (f *fakeUserRepo) Create(_ context.Context, _ iam.TenantScope, u *iam.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.ID] = f.clone(u)
	return nil
}
func (f *fakeUserRepo) Update(context.Context, iam.TenantScope, *iam.User) error { return nil }
func (f *fakeUserRepo) GetByID(_ context.Context, _ iam.TenantScope, id iam.ID) (*iam.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, iam.ErrNotFound
	}
	return f.clone(u), nil
}
func (f *fakeUserRepo) List(context.Context, iam.TenantScope, iam.Page) ([]iam.User, error) {
	return nil, nil
}
func (f *fakeUserRepo) SoftDelete(context.Context, iam.TenantScope, iam.ID) error { return nil }
func (f *fakeUserRepo) GetByEmailGlobal(_ context.Context, email iam.Email) ([]iam.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []iam.User
	for _, u := range f.users {
		if u.Email == email {
			out = append(out, *f.clone(u))
		}
	}
	return out, nil
}
func (f *fakeUserRepo) GetByEmailInOrg(_ context.Context, orgID iam.ID, email iam.Email) (*iam.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.OrganizationID == orgID && u.Email == email {
			return f.clone(u), nil
		}
	}
	return nil, iam.ErrNotFound
}
func (f *fakeUserRepo) SetRoles(_ context.Context, _ iam.TenantScope, id iam.ID, roles []iam.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roleGrants[id] = append([]iam.ID(nil), roles...)
	return nil
}
func (f *fakeUserRepo) RecordLoginSuccess(_ context.Context, id iam.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		u.FailedLoginCount = 0
		u.LockedUntil = nil
		u.LastLoginAt = &at
	}
	return nil
}
func (f *fakeUserRepo) RecordLoginFailure(_ context.Context, id iam.ID, lockUntil *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		u.FailedLoginCount++
		u.LockedUntil = lockUntil
	}
	return nil
}
func (f *fakeUserRepo) UpdatePasswordHash(_ context.Context, id iam.ID, hash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		u.PasswordHash = hash
	}
	return nil
}

func (f *fakeUserRepo) SetMustChangePassword(_ context.Context, id iam.ID, must bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[id]; ok {
		u.MustChangePassword = must
	}
	return nil
}

// fakeOrgRepo is a minimal iam.OrganizationRepository.
type fakeOrgRepo struct{ bySlug map[string]*iam.Organization }

func newFakeOrgRepo() *fakeOrgRepo                                                      { return &fakeOrgRepo{bySlug: map[string]*iam.Organization{}} }
func (f *fakeOrgRepo) Create(context.Context, iam.TenantScope, *iam.Organization) error { return nil }
func (f *fakeOrgRepo) Update(context.Context, iam.TenantScope, *iam.Organization) error { return nil }
func (f *fakeOrgRepo) GetByID(context.Context, iam.TenantScope, iam.ID) (*iam.Organization, error) {
	return nil, iam.ErrNotFound
}
func (f *fakeOrgRepo) GetBySlug(_ context.Context, slug string) (*iam.Organization, error) {
	if o, ok := f.bySlug[slug]; ok {
		return o, nil
	}
	return nil, iam.ErrNotFound
}
func (f *fakeOrgRepo) List(context.Context, iam.TenantScope, iam.Page) ([]iam.Organization, error) {
	return nil, nil
}

// fakeRoleRepo is a no-op iam.RoleRepository.
type fakeRoleRepo struct{}

func (fakeRoleRepo) List(context.Context, iam.TenantScope, iam.Page) ([]iam.Role, error) {
	return nil, nil
}
func (fakeRoleRepo) GetByID(context.Context, iam.TenantScope, iam.ID) (*iam.Role, error) {
	return nil, iam.ErrNotFound
}
func (fakeRoleRepo) Create(context.Context, iam.TenantScope, *iam.Role) error { return nil }
func (fakeRoleRepo) SetPermissions(context.Context, iam.TenantScope, iam.ID, []string) error {
	return nil
}
func (fakeRoleRepo) ListPermissions(context.Context) ([]iam.Permission, error) { return nil, nil }
func (fakeRoleRepo) GetDeviceAccess(context.Context, iam.TenantScope, iam.ID) (*iam.RoleDeviceAccess, error) {
	return &iam.RoleDeviceAccess{Scope: iam.DeviceScopeAll}, nil
}
func (fakeRoleRepo) SetDeviceAccess(context.Context, iam.TenantScope, iam.ID, iam.RoleDeviceAccess) error {
	return nil
}

// fakeSessionRepo is an in-memory iam.AuthSessionRepository. It holds a reference
// to the user repo so ListActive/FamilyOwner can resolve owner email + org the
// way the real repo does with a join.
type fakeSessionRepo struct {
	mu     sync.Mutex
	byID   map[iam.ID]*iam.AuthSession
	byHash map[string]iam.ID
	users  *fakeUserRepo
}

func newFakeSessionRepo(users *fakeUserRepo) *fakeSessionRepo {
	return &fakeSessionRepo{byID: map[iam.ID]*iam.AuthSession{}, byHash: map[string]iam.ID{}, users: users}
}
func (f *fakeSessionRepo) Create(_ context.Context, s *iam.AuthSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *s
	f.byID[s.ID] = &cp
	f.byHash[string(s.RefreshTokenHash)] = s.ID
	return nil
}
func (f *fakeSessionRepo) GetByTokenHash(_ context.Context, hash []byte) (*iam.AuthSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byHash[string(hash)]
	if !ok {
		return nil, iam.ErrRefreshInvalid
	}
	cp := *f.byID[id]
	return &cp, nil
}
func (f *fakeSessionRepo) Revoke(_ context.Context, id iam.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.byID[id]; ok && s.RevokedAt == nil {
		s.RevokedAt = &at
	}
	return nil
}
func (f *fakeSessionRepo) RevokeFamily(_ context.Context, familyID iam.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.FamilyID == familyID && s.RevokedAt == nil {
			s.RevokedAt = &at
		}
	}
	return nil
}
func (f *fakeSessionRepo) RevokeAllForUser(_ context.Context, userID iam.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.UserID == userID && s.RevokedAt == nil {
			s.RevokedAt = &at
		}
	}
	return nil
}

// ownerOf resolves a user's email + org via the wired user repo (best effort).
func (f *fakeSessionRepo) ownerOf(userID iam.ID) (string, iam.ID) {
	if f.users == nil {
		return "", iam.ID{}
	}
	u, err := f.users.GetByID(context.Background(), iam.TenantScope{IsSuperAdmin: true}, userID)
	if err != nil {
		return "", iam.ID{}
	}
	return u.Email.String(), u.OrganizationID
}

func (f *fakeSessionRepo) ListActive(_ context.Context, q iam.SessionQuery) ([]iam.AuthSessionView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	firstSeen := map[iam.ID]time.Time{}
	for _, s := range f.byID {
		if fs, ok := firstSeen[s.FamilyID]; !ok || s.CreatedAt.Before(fs) {
			firstSeen[s.FamilyID] = s.CreatedAt
		}
	}
	var out []iam.AuthSessionView
	for _, s := range f.byID {
		if s.RevokedAt != nil {
			continue // only the live row of each family
		}
		email, orgID := f.ownerOf(s.UserID)
		if q.UserID != nil && *q.UserID != s.UserID {
			continue
		}
		if q.OrgID != nil && *q.OrgID != orgID {
			continue
		}
		out = append(out, iam.AuthSessionView{
			FamilyID: s.FamilyID, UserID: s.UserID, Email: email, IP: s.IP, UserAgent: s.UserAgent,
			SignedInAt: firstSeen[s.FamilyID], LastSeenAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
		})
	}
	return out, nil
}

func (f *fakeSessionRepo) FamilyOwner(_ context.Context, familyID iam.ID) (iam.ID, iam.ID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.FamilyID == familyID {
			_, orgID := f.ownerOf(s.UserID)
			return s.UserID, orgID, nil
		}
	}
	return iam.ID{}, iam.ID{}, iam.ErrNotFound
}

// nopAudit and nopThrottle are inert test doubles.
type nopAudit struct{}

func (nopAudit) Record(context.Context, audit.Event) error { return nil }

type nopThrottle struct{}

func (nopThrottle) Allow(context.Context, string) (bool, time.Duration, error) {
	return true, 0, nil
}
func (nopThrottle) Fail(context.Context, string) error  { return nil }
func (nopThrottle) Reset(context.Context, string) error { return nil }

// fixedClock returns a constant time.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }
