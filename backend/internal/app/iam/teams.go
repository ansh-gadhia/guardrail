package iam

import (
	"context"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Team use cases.
//
// Every mutation here changes who can reach which devices, which is the same
// class of power as editing a role's permissions — so every one of them is
// audited, and the detail records what changed in terms an administrator
// reviewing the trail can act on (which team, how many members, which levels),
// not just that a write happened.

// ErrTeamsUnavailable is returned when the deployment was built without a team
// repository. It is its own answer rather than a panic or a generic 500: a
// feature that is not wired should say so.
var ErrTeamsUnavailable = iam.ErrNotFound

// ListTeams returns every team in the actor's organization.
func (s *Service) ListTeams(ctx context.Context, actor iam.Claims) ([]iam.Team, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	return s.teams.List(ctx, actor.Scope())
}

// GetTeam returns one team.
func (s *Service) GetTeam(ctx context.Context, actor iam.Claims, id iam.ID) (*iam.Team, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	return s.teams.GetByID(ctx, actor.Scope(), id)
}

// CreateTeam creates a team.
func (s *Service) CreateTeam(ctx context.Context, actor iam.Claims, t iam.Team, meta ReqMeta) (*iam.Team, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := s.teams.Create(ctx, actor.Scope(), &t); err != nil {
		return nil, err
	}
	s.recordTeam(ctx, actor, "team.create", t.ID, meta, map[string]any{
		"name": t.Name, "all_devices_level": string(t.AllDevicesLevel),
	})
	return &t, nil
}

// UpdateTeam renames a team and resets its blanket grant.
func (s *Service) UpdateTeam(ctx context.Context, actor iam.Claims, t iam.Team, meta ReqMeta) (*iam.Team, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := s.teams.Update(ctx, actor.Scope(), &t); err != nil {
		return nil, err
	}
	// Read back rather than returning the input: the caller sees member count and
	// timestamps as stored, and a rename that collided is reported by Update
	// rather than reflected back as if it had succeeded.
	out, err := s.teams.GetByID(ctx, actor.Scope(), t.ID)
	if err != nil {
		return nil, err
	}
	s.recordTeam(ctx, actor, "team.update", t.ID, meta, map[string]any{
		"name": t.Name, "all_devices_level": string(t.AllDevicesLevel),
	})
	return out, nil
}

// DeleteTeam removes a team and, with it, every grant it conferred.
func (s *Service) DeleteTeam(ctx context.Context, actor iam.Claims, id iam.ID, meta ReqMeta) error {
	if s.teams == nil {
		return ErrTeamsUnavailable
	}
	// Read first so the audit entry can name the team. After the delete there is
	// nothing left to name it with, and "team <uuid> deleted" is an entry nobody
	// can act on months later.
	t, err := s.teams.GetByID(ctx, actor.Scope(), id)
	if err != nil {
		return err
	}
	if err := s.teams.Delete(ctx, actor.Scope(), id); err != nil {
		return err
	}
	s.recordTeam(ctx, actor, "team.delete", id, meta, map[string]any{
		"name": t.Name, "members": t.MemberCount,
	})
	return nil
}

// ListTeamMembers returns a team's membership.
func (s *Service) ListTeamMembers(ctx context.Context, actor iam.Claims, id iam.ID) ([]iam.TeamMember, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	return s.teams.ListMembers(ctx, actor.Scope(), id)
}

// SetTeamMembers replaces a team's membership.
func (s *Service) SetTeamMembers(ctx context.Context, actor iam.Claims, id iam.ID, userIDs []iam.ID, meta ReqMeta) error {
	if s.teams == nil {
		return ErrTeamsUnavailable
	}
	if err := s.teams.SetMembers(ctx, actor.Scope(), id, dedupeIDs(userIDs)); err != nil {
		return err
	}
	s.recordTeam(ctx, actor, "team.set_members", id, meta, map[string]any{"members": len(userIDs)})
	return nil
}

// ListTeamsForUser returns the teams one user belongs to.
func (s *Service) ListTeamsForUser(ctx context.Context, actor iam.Claims, userID iam.ID) ([]iam.Team, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	return s.teams.ListForUser(ctx, actor.Scope(), userID)
}

// GetTeamGrants returns a team's device grants.
func (s *Service) GetTeamGrants(ctx context.Context, actor iam.Claims, id iam.ID) (*iam.TeamGrants, error) {
	if s.teams == nil {
		return nil, ErrTeamsUnavailable
	}
	return s.teams.GetGrants(ctx, actor.Scope(), id)
}

// SetTeamGrants replaces a team's device grants.
//
// An empty grant set is valid and means the team confers nothing — which is a
// team that exists for membership alone, and a legitimate intermediate state
// while one is being set up.
func (s *Service) SetTeamGrants(ctx context.Context, actor iam.Claims, id iam.ID, g iam.TeamGrants, meta ReqMeta) error {
	if s.teams == nil {
		return ErrTeamsUnavailable
	}
	if err := g.Validate(); err != nil {
		return err
	}
	if err := s.teams.SetGrants(ctx, actor.Scope(), id, g); err != nil {
		return err
	}
	// Levels are recorded, not just counts. "Three groups granted" does not
	// distinguish read-only visibility from full management of the same estate,
	// and that difference is the whole reason levels exist.
	levels := map[string]int{}
	for _, gr := range g.Groups {
		levels[string(gr.Level)]++
	}
	s.recordTeam(ctx, actor, "team.set_grants", id, meta, map[string]any{
		"groups": len(g.Groups), "device_types": len(g.DeviceTypes), "levels": levels,
	})
	return nil
}

// dedupeIDs removes repeats while preserving order. The repository counts rows
// affected to detect an id it could not see, and a duplicate would make that
// count disagree with the input length and report a spurious ErrNotFound.
func dedupeIDs(in []iam.ID) []iam.ID {
	seen := make(map[iam.ID]struct{}, len(in))
	out := make([]iam.ID, 0, len(in))
	for _, id := range in {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (s *Service) recordTeam(ctx context.Context, actor iam.Claims, action string, id iam.ID, meta ReqMeta, detail map[string]any) {
	s.record(ctx, audit.Event{
		OrganizationID: &actor.OrganizationID, Action: action, Category: audit.CategoryRole,
		ActorID: &actor.UserID, ActorEmail: actor.Email,
		TargetType: "team", TargetID: id.String(),
		IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess, Detail: detail,
	})
}
