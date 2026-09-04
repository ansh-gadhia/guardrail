package iam

import (
	"context"
	"strings"
	"time"
)

// Teams: the second axis of device authorization.
//
// A role answers "what may this person do" — connect, terminate, download a
// recording, approve a request. A team answers "which devices may they do it
// to". Before teams the second question was answered on the role too
// (RoleDeviceAccess), which forced one object to carry both and made the role
// list grow as roles × teams: IT Operator, IT Auditor, Security Operator,
// Security Auditor, and another pair every time either axis grew.
//
// The two are ANDed at every enforcement point, and the order is what keeps
// this from becoming a competing permission system: a team grant is a CEILING
// on reach and never a grant of capability. Granting an Auditor 'manage' over a
// group gives them nothing new, because the Auditor role holds no device:write.

// AccessLevel is how far a grant reaches into the devices it covers.
type AccessLevel string

const (
	// AccessNone is the absence of a grant. It is a real value rather than the
	// empty string so that "this user reaches nothing" is something a function
	// can return and a caller can compare, instead of an ambiguous zero value.
	AccessNone AccessLevel = "none"
	// AccessView makes the device visible — inventory, dashboard counts, the
	// status feed — and nothing more.
	AccessView AccessLevel = "view"
	// AccessConnect adds the right to broker a session to it.
	AccessConnect AccessLevel = "connect"
	// AccessManage adds the right to edit the device and its credential
	// bindings.
	AccessManage AccessLevel = "manage"
)

// Rank orders the levels. It mirrors app_access_rank() in migration 0034 — the
// two must agree, and the test in team_test.go is what holds them together.
func (l AccessLevel) Rank() int {
	switch l {
	case AccessManage:
		return 3
	case AccessConnect:
		return 2
	case AccessView:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether this level covers the one asked for.
func (l AccessLevel) AtLeast(want AccessLevel) bool { return l.Rank() >= want.Rank() }

// Valid reports whether the level is one a grant may be stored with. AccessNone
// is deliberately excluded: a grant that grants nothing is a row that should not
// have been written, and storing it hides a mistake that a validation error
// would have shown at the point it was made.
func (l AccessLevel) Valid() bool {
	return l == AccessView || l == AccessConnect || l == AccessManage
}

// AccessLevelFromRank turns a rank back into a level, mirroring
// app_access_level() in migration 0034.
func AccessLevelFromRank(r int) AccessLevel {
	switch {
	case r >= 3:
		return AccessManage
	case r == 2:
		return AccessConnect
	case r == 1:
		return AccessView
	default:
		return AccessNone
	}
}

// NormalizeAccessLevel folds the spellings a client might send onto one token,
// returning "" for anything unrecognised so the caller can reject it rather than
// silently substituting a level nobody asked for.
func NormalizeAccessLevel(s string) AccessLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "view", "read", "read-only", "readonly":
		return AccessView
	case "connect", "use", "session":
		return AccessConnect
	case "manage", "write", "admin", "full":
		return AccessManage
	case "none", "":
		return AccessNone
	default:
		return ""
	}
}

// Team is a named group of users within one organization.
type Team struct {
	ID             ID
	OrganizationID ID
	Name           string
	Description    string
	// AllDevicesLevel is a blanket grant over every device in the organization.
	// AccessNone — the ordinary case — means no blanket grant.
	//
	// This is what an admin or platform team needs. Enumerating such a team
	// against every asset group instead produces a grant that decays: it stops
	// covering anything created afterwards, and gives no sign that it has.
	AllDevicesLevel AccessLevel
	CreatedAt       time.Time
	UpdatedAt       time.Time
	// MemberCount is a read-model convenience for listings, so the console does
	// not issue one query per team to render a column.
	MemberCount int
}

// Validate checks a team before it is written.
func (t *Team) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
	if t.Name == "" {
		return ErrInvalidInput
	}
	if len(t.Name) > 128 || len(t.Description) > 1024 {
		return ErrInvalidInput
	}
	if t.AllDevicesLevel == "" {
		t.AllDevicesLevel = AccessNone
	}
	if t.AllDevicesLevel != AccessNone && !t.AllDevicesLevel.Valid() {
		return ErrInvalidInput
	}
	return nil
}

// TeamMember is one person's membership, enriched with their email so a
// membership listing does not need a second round trip per row.
type TeamMember struct {
	UserID  ID
	Email   string
	Status  string
	AddedAt time.Time
}

// GroupGrant is a team's grant over one asset group. The grant covers the
// group's DESCENDANTS as well: a tree that does not inherit cannot be safely
// reorganised, because moving a group under another would silently revoke it.
type GroupGrant struct {
	AssetGroupID ID
	// Name is a read-model convenience for rendering; it is ignored on write.
	Name  string
	Level AccessLevel
}

// TypeGrant is a team's grant over every device of one type.
type TypeGrant struct {
	DeviceType string
	Level      AccessLevel
}

// TeamGrants is the whole grant set of one team, replaced as a unit.
//
// Replaced rather than patched because a grant set is read as a whole by the
// person editing it: "the IT team reaches these four groups" is the thing being
// decided, and an API that adds and removes one row at a time turns a single
// decision into a sequence that can be interrupted half-applied.
type TeamGrants struct {
	Groups      []GroupGrant
	DeviceTypes []TypeGrant
}

// Validate normalises and checks a grant set.
func (g *TeamGrants) Validate() error {
	seenGroup := make(map[ID]struct{}, len(g.Groups))
	for i := range g.Groups {
		if g.Groups[i].Level == "" {
			g.Groups[i].Level = AccessConnect
		}
		if !g.Groups[i].Level.Valid() {
			return ErrInvalidInput
		}
		if _, dup := seenGroup[g.Groups[i].AssetGroupID]; dup {
			return ErrInvalidInput
		}
		seenGroup[g.Groups[i].AssetGroupID] = struct{}{}
	}
	seenType := make(map[string]struct{}, len(g.DeviceTypes))
	for i := range g.DeviceTypes {
		g.DeviceTypes[i].DeviceType = strings.TrimSpace(g.DeviceTypes[i].DeviceType)
		if g.DeviceTypes[i].DeviceType == "" {
			return ErrInvalidInput
		}
		if g.DeviceTypes[i].Level == "" {
			g.DeviceTypes[i].Level = AccessConnect
		}
		if !g.DeviceTypes[i].Level.Valid() {
			return ErrInvalidInput
		}
		key := strings.ToLower(g.DeviceTypes[i].DeviceType)
		if _, dup := seenType[key]; dup {
			return ErrInvalidInput
		}
		seenType[key] = struct{}{}
	}
	return nil
}

// TeamRepository persists teams, their membership and their grants.
type TeamRepository interface {
	Create(ctx context.Context, s TenantScope, t *Team) error
	Update(ctx context.Context, s TenantScope, t *Team) error
	Delete(ctx context.Context, s TenantScope, id ID) error
	GetByID(ctx context.Context, s TenantScope, id ID) (*Team, error)
	List(ctx context.Context, s TenantScope) ([]Team, error)

	ListMembers(ctx context.Context, s TenantScope, teamID ID) ([]TeamMember, error)
	SetMembers(ctx context.Context, s TenantScope, teamID ID, userIDs []ID) error
	// ListForUser returns the teams one user belongs to, for the console's user
	// detail view and for explaining an access decision.
	ListForUser(ctx context.Context, s TenantScope, userID ID) ([]Team, error)

	GetGrants(ctx context.Context, s TenantScope, teamID ID) (*TeamGrants, error)
	SetGrants(ctx context.Context, s TenantScope, teamID ID, g TeamGrants) error
}
