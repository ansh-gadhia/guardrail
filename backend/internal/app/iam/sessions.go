package iam

import (
	"context"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// sessionAdminPerm gates the cross-user "who is signed in" view and revoking
// another user's session. It reuses the existing user-directory permissions so
// no new permission has to be seeded.
const (
	sessionReadPerm  = "user:read"
	sessionWritePerm = "user:write"
)

// ListSessions returns the live login sessions the actor is allowed to see. A
// caller with user:read gets the whole picture (their tenant, or everything for a
// super admin) so operators can answer "who is signed in right now"; everyone
// else sees only their own. Passing selfOnly forces the own-sessions view even
// for an admin. currentRefresh is the caller's refresh cookie (may be empty); it
// is used only to flag which returned session is the one making this request.
func (s *Service) ListSessions(ctx context.Context, actor iam.Claims, currentRefresh string, selfOnly bool) ([]SessionView, error) {
	var q iam.SessionQuery
	switch {
	case selfOnly || !actor.Has(sessionReadPerm):
		uid := actor.UserID
		q.UserID = &uid
	case !actor.IsSuperAdmin:
		oid := actor.OrganizationID
		q.OrgID = &oid
	}
	// super admin, not selfOnly → no filter: every active session.

	views, err := s.sessions.ListActive(ctx, q)
	if err != nil {
		return nil, err
	}

	// Identify the caller's current session by hashing their refresh cookie and
	// finding its family. A missing/expired cookie simply means nothing is marked.
	var currentFamily iam.ID
	if currentRefresh != "" {
		if sess, e := s.sessions.GetByTokenHash(ctx, s.refresh.Hash(currentRefresh)); e == nil {
			currentFamily = sess.FamilyID
		}
	}

	out := make([]SessionView, 0, len(views))
	for _, v := range views {
		out = append(out, SessionView{
			ID: v.FamilyID, UserID: v.UserID, Email: v.Email, IP: v.IP, UserAgent: v.UserAgent,
			SignedInAt: v.SignedInAt, LastSeenAt: v.LastSeenAt, ExpiresAt: v.ExpiresAt,
			Current: currentFamily != (iam.ID{}) && v.FamilyID == currentFamily,
			Self:    v.UserID == actor.UserID,
		})
	}
	return out, nil
}

// RevokeSession force-signs-out a login session (whole refresh-token family). A
// user may always revoke their own; revoking someone else's requires user:write
// and, for a non-super-admin, that the target is in the actor's organization.
func (s *Service) RevokeSession(ctx context.Context, actor iam.Claims, familyID iam.ID, meta ReqMeta) error {
	ownerID, orgID, err := s.sessions.FamilyOwner(ctx, familyID)
	if err != nil {
		return err // ErrNotFound when the family is unknown
	}
	if ownerID != actor.UserID {
		if !actor.Has(sessionWritePerm) {
			return iam.ErrPermissionDenied
		}
		if !actor.IsSuperAdmin && orgID != actor.OrganizationID {
			return iam.ErrPermissionDenied
		}
	}
	if err := s.sessions.RevokeFamily(ctx, familyID, s.clock.Now()); err != nil {
		return err
	}
	s.record(ctx, audit.Event{
		OrganizationID: &orgID, Action: "auth.session_revoke", Category: audit.CategoryAuth,
		ActorID: &actor.UserID, ActorEmail: actor.Email, IP: meta.IP, UserAgent: meta.UserAgent,
		Result: audit.ResultSuccess,
		Detail: map[string]any{"target_user": ownerID.String(), "family": familyID.String()},
	})
	return nil
}
