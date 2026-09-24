package iam

import (
	"context"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"

	"github.com/google/uuid"
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
	// Adding somebody to a team, or taking them off it, changes what they can
	// reach: the hierarchy applies to each person whose membership changes.
	// Those already on it and staying are not being managed.
	current, err := s.teams.ListMembers(ctx, actor.Scope(), id)
	if err != nil {
		return err
	}
	was := map[iam.ID]bool{}
	for _, m := range current {
		was[m.UserID] = true
	}
	will := map[iam.ID]bool{}
	for _, uid := range dedupeIDs(userIDs) {
		will[uid] = true
		if !was[uid] {
			if _, err := s.guardRank(ctx, actor, uid, "change their teams"); err != nil {
				return err
			}
		}
	}
	for uid := range was {
		if !will[uid] {
			if _, err := s.guardRank(ctx, actor, uid, "change their teams"); err != nil {
				return err
			}
		}
	}
	if err := s.teams.SetMembers(ctx, actor.Scope(), id, dedupeIDs(userIDs)); err != nil {
		return err
	}
	s.recordTeam(ctx, actor, "team.set_members", id, meta, map[string]any{"members": len(userIDs)})
	return nil
}

// AddUserToTeams puts one person into each of the given teams, keeping whoever
// is already in them.
//
// SetMembers REPLACES a team's membership, which is right for the team editor —
// somebody looking at a list and deciding who is on it — and wrong for adding a
// person: used directly it would empty the team and leave one member. So this
// reads the current membership and adds to it.
//
// Teams that do not exist, or are out of the actor's scope, are reported rather
// than skipped: being put in no team when the form said otherwise is the kind of
// quiet failure that is discovered when somebody cannot reach a device.
func (s *Service) AddUserToTeams(ctx context.Context, actor iam.Claims, userID iam.ID, teamIDs []iam.ID, meta ReqMeta) error {
	if len(teamIDs) == 0 {
		return nil
	}
	if s.teams == nil {
		return ErrTeamsUnavailable
	}
	if _, err := s.guardRank(ctx, actor, userID, "change their teams"); err != nil {
		return err
	}
	for _, tid := range dedupeIDs(teamIDs) {
		members, err := s.teams.ListMembers(ctx, actor.Scope(), tid)
		if err != nil {
			return err
		}
		ids := make([]iam.ID, 0, len(members)+1)
		already := false
		for _, m := range members {
			ids = append(ids, m.UserID)
			if m.UserID == userID {
				already = true
			}
		}
		if already {
			continue
		}
		ids = append(ids, userID)
		if err := s.teams.SetMembers(ctx, actor.Scope(), tid, ids); err != nil {
			return err
		}
		s.recordTeam(ctx, actor, "team.add_member", tid, meta,
			map[string]any{"user_id": uuid.UUID(userID).String(), "members": len(ids)})
	}
	return nil
}

// SetUserTeams makes one person a member of exactly these teams: added to the
// ones they are not in, removed from the ones no longer listed, and every other
// member of every team left exactly where they were.
//
// This is the person-shaped view of membership. The team editor asks "who is on
// this team"; the access-control page asks "what teams is this person on", and
// answering the second with the first's replace-the-whole-list primitive would
// either empty teams or require an admin to open every team to move one person.
func (s *Service) SetUserTeams(ctx context.Context, actor iam.Claims, userID iam.ID, teamIDs []iam.ID, meta ReqMeta) error {
	if s.teams == nil {
		return ErrTeamsUnavailable
	}
	if _, err := s.guardRank(ctx, actor, userID, "change their teams"); err != nil {
		return err
	}
	current, err := s.teams.ListForUser(ctx, actor.Scope(), userID)
	if err != nil {
		return err
	}
	want := map[iam.ID]bool{}
	for _, id := range dedupeIDs(teamIDs) {
		want[id] = true
	}
	have := map[iam.ID]bool{}
	for _, t := range current {
		have[t.ID] = true
	}

	var add []iam.ID
	for id := range want {
		if !have[id] {
			add = append(add, id)
		}
	}
	if err := s.AddUserToTeams(ctx, actor, userID, add, meta); err != nil {
		return err
	}

	for id := range have {
		if want[id] {
			continue
		}
		members, err := s.teams.ListMembers(ctx, actor.Scope(), id)
		if err != nil {
			return err
		}
		keep := make([]iam.ID, 0, len(members))
		for _, m := range members {
			if m.UserID != userID {
				keep = append(keep, m.UserID)
			}
		}
		if err := s.teams.SetMembers(ctx, actor.Scope(), id, keep); err != nil {
			return err
		}
		s.recordTeam(ctx, actor, "team.remove_member", id, meta,
			map[string]any{"user_id": uuid.UUID(userID).String(), "members": len(keep)})
	}
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
