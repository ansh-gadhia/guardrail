package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// PermApprovalBypass exempts its holder's own connects from the approval gate.
//
// It says nothing about deciding other people's requests — that is
// approval:decide. Treating the two as one check would delete an organization's
// entire approval capacity the moment somebody granted bypass to the admins,
// because the only people who outrank an operator would stop being asked.
const PermApprovalBypass = "approval:bypass"

// PermApprovalDecide lets its holder approve or deny other people's requests.
const PermApprovalDecide = "approval:decide"

// gateOutcome is what the approval gate decided about one connect.
type gateOutcome struct {
	// allow lets the connect proceed now.
	allow bool
	// request is the pending request the caller must wait on, when !allow.
	request *access.Request
	// redeem is an already-approved request this connect should consume.
	redeem *access.Request
	// reason names why a connect was allowed without asking, for the audit trail.
	reason string
	// needsReason means the caller must ask, and has not said why yet. It is not
	// a failure: the console's first Connect deliberately carries no reason,
	// because that probe is how it finds out the device is gated for THIS caller
	// at all — every exemption above is invisible from the browser.
	needsReason bool
}

// ConnectOptions carries what the requester said when asking for access.
type ConnectOptions struct {
	// Reason is why they need it. Mandatory on a gated device.
	Reason string
	// Minutes is the window they asked for.
	Minutes int
	// Emergency takes access now and submits it for review afterwards.
	Emergency bool
	// RequestID redeems a specific approved request.
	RequestID *uuid.UUID
}

// approvalGate decides whether this connect may proceed, and raises a request if
// not.
//
// Order matters and is not arbitrary. It runs AFTER entitlement — no point
// waking an approver for somebody whose roles cannot reach the device — and
// BEFORE the credential pre-flight, because resolving a secret for a request
// that may sit pending for half an hour is work done on a hope.
func (s *Service) approvalGate(ctx context.Context, actor iam.Claims, ep access.Endpoint,
	deviceID uuid.UUID, opts ConnectOptions, meta ReqMeta) (gateOutcome, error) {
	if !ep.RequiresApproval || s.requests == nil {
		return gateOutcome{allow: true}, nil
	}
	now := s.clock.Now()
	// Normalized once, here, so every check below means the same thing by "no
	// reason" and the stored request carries the trimmed text. opts is a copy.
	opts.Reason = strings.TrimSpace(opts.Reason)

	// 1. Administrators. A permission rather than a role name, so a custom role
	//    can be exempted without a code change and so the role editor SHOWS who
	//    is exempt.
	if actor.IsSuperAdmin || actor.Has(PermApprovalBypass) {
		return gateOutcome{allow: true, reason: "bypass"}, nil
	}

	// 2. The device's own registrar. Waiting for permission to reach something
	//    you registered yourself is friction with no control behind it — and the
	//    codebase already treats ownership this way for the recording policy.
	//
	//    The limit is the whole reason this is safe. A device dropped into an
	//    asset group inherits credentials its creator has never seen, so an
	//    unqualified owner exemption would turn "register a device in the right
	//    group" into an ungated path to every secret in the vault.
	if ep.CreatedBy != nil && *ep.CreatedBy == actor.UserID {
		inherited, err := s.creds.CredentialInherited(ctx, scopeOf(actor), deviceID, actor.UserID)
		if err != nil {
			return gateOutcome{}, err
		}
		if !inherited {
			return gateOutcome{allow: true, reason: "device_owner"}, nil
		}
	}

	// 3. A standing grant — somebody already pressed "allow all time".
	if s.grants != nil {
		g, err := s.grants.Live(ctx, scopeOf(actor), actor.UserID, deviceID, now)
		switch {
		case err == nil && g.Live(now):
			return gateOutcome{allow: true, reason: "standing_grant"}, nil
		case err != nil && !errors.Is(err, access.ErrNotFound):
			return gateOutcome{}, err
		}
	}

	// 4. An approval already in hand.
	existing, err := s.requests.PendingFor(ctx, scopeOf(actor), actor.UserID, deviceID, now)
	if err != nil && !errors.Is(err, access.ErrNotFound) {
		return gateOutcome{}, err
	}
	// An approval already in hand beats everything below: redeeming it costs
	// nobody a review, which an emergency does.
	if existing != nil && existing.Redeemable(now) {
		return gateOutcome{allow: true, redeem: existing, reason: "approved"}, nil
	}

	// 5. Emergency: taken now, reviewed after.
	//
	// Checked BEFORE the outstanding-request branch below, deliberately. Somebody
	// reaching for the emergency button has almost always tried the ordinary path
	// first — that pending request is *why* they are here — and letting it swallow
	// the emergency would mean the door only works for people who never knocked.
	if opts.Emergency {
		if opts.Reason == "" {
			return gateOutcome{needsReason: true}, nil
		}
		if err := s.emergencyQuota(ctx, actor, now); err != nil {
			s.recordAuditDetail(ctx, actor, "approval.emergency_refused", &access.Session{DeviceID: deviceID}, meta,
				audit.ResultDenied, map[string]any{"reason": opts.Reason})
			return gateOutcome{}, err
		}
		req, rerr := s.raiseRequest(ctx, actor, ep, deviceID, opts, now, true)
		if rerr != nil {
			return gateOutcome{}, rerr
		}
		// The ordinary request is moot now: they have the access. Withdrawing it
		// keeps the approver queue honest rather than leaving somebody to decide
		// a question that has already been answered by other means.
		if existing != nil && existing.Status == access.RequestPending {
			if cerr := s.requests.Cancel(ctx, scopeOf(actor), existing.ID, actor.UserID); cerr != nil {
				s.log.Warn("emergency: could not withdraw the superseded request", zap.Error(cerr))
			}
		}
		s.recordAuditDetail(ctx, actor, "approval.emergency", &access.Session{DeviceID: deviceID}, meta,
			audit.ResultSuccess, map[string]any{"request_id": req.ID.String(), "reason": opts.Reason})
		return gateOutcome{allow: true, redeem: req, reason: "emergency"}, nil
	}

	// 6. Already waiting on somebody. Return the same request rather than raising
	// a second one: pressing Connect twice should show one request, not spam the
	// approver queue with duplicates.
	if existing != nil && existing.Status == access.RequestPending {
		return gateOutcome{request: existing}, nil
	}

	// 7. Ask — if we know what to tell the approver.
	//
	// Below the outstanding-request branch deliberately: pressing Connect a
	// second time should surface the request already waiting, not demand a reason
	// for one that has been given.
	if opts.Reason == "" {
		return gateOutcome{needsReason: true}, nil
	}
	req, err := s.raiseRequest(ctx, actor, ep, deviceID, opts, now, false)
	if err != nil {
		return gateOutcome{}, err
	}
	// Pending, not denied. Nobody has refused anything here: a request has been
	// filed and is waiting on an approver, who very often goes on to approve it
	// seconds later. Recorded as denied, this row sat in the Audit Log
	// contradicting the approval.granted row directly beneath it, and no
	// correction is possible after the fact — the chain is append-only.
	s.recordAuditDetail(ctx, actor, "approval.requested", &access.Session{DeviceID: deviceID}, meta,
		audit.ResultPending, map[string]any{"request_id": req.ID.String(), "reason": opts.Reason})
	return gateOutcome{request: req}, nil
}

// emergencyQuota refuses a break-glass connect from somebody who has already
// taken as many as policy allows this window.
//
// This is what keeps the approval gate from being advisory. Emergency access
// stays reachable by anybody the gate applies to, on purpose — a door people can
// see beats a wall they climb by sharing the break-glass credential — but a door
// with no counter on it means nobody ever has to ask for anything.
//
// The refusal names the moment the quota frees up. "Denied" on its own, during
// the incident somebody reached for this button in, is the least useful thing
// the platform could say: they need to know whether to wait four minutes or four
// days before deciding to go and wake an approver instead.
func (s *Service) emergencyQuota(ctx context.Context, actor iam.Claims, now time.Time) error {
	if s.cfg.EmergencyQuota <= 0 || s.cfg.EmergencyWindow <= 0 {
		return nil
	}
	since := now.Add(-s.cfg.EmergencyWindow)
	n, oldest, err := s.requests.CountEmergenciesSince(ctx, scopeOf(actor), actor.UserID, since)
	if err != nil {
		return err
	}
	if n < s.cfg.EmergencyQuota {
		return nil
	}
	// Fail closed if the oldest is somehow missing: a count at the limit with no
	// timestamp still means the limit is reached.
	if oldest.IsZero() {
		return fmt.Errorf("%w: you have taken emergency access %d times in the last %s, which is the limit. "+
			"Ask for approval instead", access.ErrEmergencyQuota, n, humanDuration(s.cfg.EmergencyWindow))
	}
	return fmt.Errorf("%w: you have taken emergency access %d times in the last %s, which is the limit. "+
		"The next one frees up %s. Ask for approval instead, or have an administrator review the ones outstanding",
		access.ErrEmergencyQuota, n, humanDuration(s.cfg.EmergencyWindow),
		oldest.Add(s.cfg.EmergencyWindow).UTC().Format("on 2 Jan at 15:04 UTC"))
}

// humanDuration renders a policy window the way somebody would say it, so a
// refusal reads as a sentence rather than "168h0m0s".
func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return d.String()
	}
}

// raiseRequest validates and stores a new access request.
func (s *Service) raiseRequest(ctx context.Context, actor iam.Claims, ep access.Endpoint,
	deviceID uuid.UUID, opts ConnectOptions, now time.Time, emergency bool) (*access.Request, error) {
	// Reachable only from an API client now — the gate answers a reasonless
	// console probe long before this. Wrapped so the 400 says what is missing
	// instead of "access: invalid".
	if strings.TrimSpace(opts.Reason) == "" {
		return nil, fmt.Errorf("%w: a reason is required to ask for access to this device", access.ErrInvalid)
	}
	// The rate limit exists so one frustrated operator cannot bury every approver
	// in notifications. It must NOT apply to an emergency: somebody reaching for
	// that button has usually been hammering the ordinary one first, so the
	// person most likely to be at the cap is exactly the person in a crisis —
	// and locking them out is how the emergency door stops being a door.
	if !emergency {
		pending, err := s.requests.CountPending(ctx, scopeOf(actor), actor.UserID)
		if err != nil {
			return nil, err
		}
		if pending >= access.MaxPendingPerUser {
			return nil, access.ErrTooManyRequests
		}
	}

	level := actor.Level()
	// Refuse to raise a request nobody could ever decide. The alternative is a
	// person waiting half an hour on an approval that was never going to arrive,
	// discovering the misconfiguration at exactly the wrong moment.
	//
	// Emergencies skip the check: they are granted immediately and reviewed
	// afterwards, so there is nobody to wait for.
	if !emergency && s.ranker != nil {
		n, cerr := s.ranker.ApproversAbove(ctx, scopeOf(actor), level)
		if cerr != nil {
			return nil, cerr
		}
		if n == 0 {
			return nil, access.ErrNoApprover
		}
	}

	minutes := opts.Minutes
	if minutes <= 0 {
		minutes = int(s.cfg.DefaultWindow / time.Minute)
	}
	req := &access.Request{
		ID: uuid.New(), OrganizationID: actor.OrganizationID, UserID: actor.UserID,
		DeviceID: deviceID, Status: access.RequestPending, Reason: opts.Reason,
		RequestedMinutes: minutes, MinApprovals: ep.MinApprovals, RequesterLevel: level,
		IsEmergency: emergency, ExpiresAt: now.Add(access.DefaultRequestTTL),
	}
	if emergency {
		// An emergency is not pending anything: it is already granted, and what
		// remains is the review.
		req.Status = access.RequestApproved
		req.GrantedMinutes = &minutes
	}
	if err := s.requests.Create(ctx, scopeOf(actor), req); err != nil {
		return nil, err
	}
	s.notifyApprovers(ctx, actor, req, emergency)
	return req, nil
}

// DecideInput is an approver's answer.
type DecideInput struct {
	// Approve or deny.
	Approve bool
	// Scope is which button was pressed: once, or always. Ignored on a denial.
	Scope access.GrantScope
	// Minutes may shorten the window the requester asked for, never lengthen it.
	Minutes int
	Note    string
	Meta    ReqMeta
}

// Decide records one approver's vote on a request.
//
// The rank check lives in the repository, inside the same transaction as the
// insert, so two approvers deciding at once cannot both read "one more needed"
// and leave a fully-approved request sitting pending.
func (s *Service) Decide(ctx context.Context, actor iam.Claims, requestID uuid.UUID, in DecideInput) (*access.Request, error) {
	if !actor.IsSuperAdmin && !actor.Has(PermApprovalDecide) {
		return nil, access.ErrForbidden
	}
	req, err := s.requests.GetByID(ctx, scopeOf(actor), requestID)
	if err != nil {
		return nil, err
	}
	if req.UserID == actor.UserID {
		// Belt and braces. Strict rank comparison already makes this impossible,
		// since nobody outranks themselves — but saying it here means the rule
		// survives somebody later deciding that equal ranks may approve.
		return nil, access.ErrCannotDecide
	}

	if in.Approve {
		minutes := req.RequestedMinutes
		if in.Minutes > 0 && in.Minutes < minutes {
			minutes = in.Minutes
		}
		scope := in.Scope
		if scope != access.GrantAlways {
			scope = access.GrantOnce
		}
		if err := s.requests.SetOutcome(ctx, scopeOf(actor), requestID, &minutes, &scope); err != nil {
			return nil, err
		}
	}

	decision := access.DecisionDeny
	if in.Approve {
		decision = access.DecisionApprove
	}
	updated, err := s.requests.AddDecision(ctx, scopeOf(actor), requestID, actor.UserID,
		access.Decision{Decision: decision, Note: in.Note}, actor.Level(), actor.IsSuperAdmin)
	if err != nil {
		return nil, err
	}

	// "Allow all time" is not a decision about this request — it is a change to
	// future authorization, so it gets a row of its own with a list and a revoke
	// path. Written only once the request is actually approved, so the second
	// approver under a two-person rule is what creates it.
	if updated.Status == access.RequestApproved && updated.GrantScope != nil &&
		*updated.GrantScope == access.GrantAlways && s.grants != nil {
		by := actor.UserID
		g := &access.Grant{
			ID: uuid.New(), OrganizationID: updated.OrganizationID, UserID: updated.UserID,
			DeviceID: updated.DeviceID, GrantedBy: &by, RequestID: &updated.ID,
		}
		if err := s.grants.Create(ctx, scopeOf(actor), g); err != nil {
			return nil, err
		}
	}

	action := "approval.denied"
	result := audit.ResultDenied
	if in.Approve {
		action, result = "approval.granted", audit.ResultSuccess
	}
	s.recordAuditDetail(ctx, actor, action, &access.Session{DeviceID: updated.DeviceID}, in.Meta, result,
		map[string]any{
			"request_id": updated.ID.String(), "requester": updated.RequesterEmail,
			"approvals": updated.Approvals(), "needed": updated.EffectiveMinApprovals(),
			"note": in.Note,
		})
	s.notifyRequester(ctx, updated, in.Approve)
	return updated, nil
}

// ListRequests returns access requests. Somebody without approval:read sees
// only their own — a requester needs to watch their request without being shown
// everybody else's.
func (s *Service) ListRequests(ctx context.Context, actor iam.Claims, f access.RequestFilter) ([]access.Request, error) {
	if !actor.IsSuperAdmin && !actor.Has("approval:read") && !actor.Has(PermApprovalDecide) {
		uid := actor.UserID
		f.UserID = &uid
	}
	return s.requests.List(ctx, scopeOf(actor), f)
}

// GetRequest loads one request. A requester may always see their own.
func (s *Service) GetRequest(ctx context.Context, actor iam.Claims, id uuid.UUID) (*access.Request, error) {
	req, err := s.requests.GetByID(ctx, scopeOf(actor), id)
	if err != nil {
		return nil, err
	}
	if req.UserID != actor.UserID && !actor.IsSuperAdmin &&
		!actor.Has("approval:read") && !actor.Has(PermApprovalDecide) {
		return nil, access.ErrForbidden
	}
	return req, nil
}

// CancelRequest withdraws a pending request the caller raised.
func (s *Service) CancelRequest(ctx context.Context, actor iam.Claims, id uuid.UUID) error {
	return s.requests.Cancel(ctx, scopeOf(actor), id, actor.UserID)
}

// ReviewEmergency signs off an emergency access after the fact. This is what
// keeps the emergency door a control rather than a hole: the access happened,
// and somebody senior has to look at it and say so.
func (s *Service) ReviewEmergency(ctx context.Context, actor iam.Claims, id uuid.UUID, note string, meta ReqMeta) error {
	if !actor.IsSuperAdmin && !actor.Has(PermApprovalDecide) {
		return access.ErrForbidden
	}
	if err := s.requests.MarkReviewed(ctx, scopeOf(actor), id, actor.UserID, note, s.clock.Now()); err != nil {
		return err
	}
	s.recordAuditDetail(ctx, actor, "approval.reviewed", &access.Session{}, meta, audit.ResultSuccess,
		map[string]any{"request_id": id.String(), "note": note})
	return nil
}

// ListGrants returns standing grants.
func (s *Service) ListGrants(ctx context.Context, actor iam.Claims, f access.GrantFilter) ([]access.Grant, error) {
	if s.grants == nil {
		return nil, nil
	}
	return s.grants.List(ctx, scopeOf(actor), f)
}

// RevokeGrant withdraws a standing grant AND terminates any session it is
// holding open.
//
// Revocation that leaves the current session running is theatre: "allow once"
// would quietly mean "allow for the next eight hours", and an administrator who
// has just cut somebody's access would watch them keep working.
func (s *Service) RevokeGrant(ctx context.Context, actor iam.Claims, id uuid.UUID, meta ReqMeta) error {
	if !actor.IsSuperAdmin && !actor.Has(PermApprovalDecide) {
		return access.ErrForbidden
	}
	g, err := s.grants.Revoke(ctx, scopeOf(actor), id, actor.UserID, s.clock.Now())
	if err != nil {
		return err
	}
	s.recordAuditDetail(ctx, actor, "grant.revoked", &access.Session{DeviceID: g.DeviceID}, meta,
		audit.ResultSuccess, map[string]any{"grant_id": g.ID.String(), "user": g.UserEmail})
	s.terminateFor(ctx, actor, g.UserID, g.DeviceID, "standing grant revoked", meta)
	return nil
}

// terminateFor ends any live session this person holds on this device.
func (s *Service) terminateFor(ctx context.Context, actor iam.Claims, userID, deviceID uuid.UUID,
	reason string, meta ReqMeta) {
	live, err := s.sessions.List(ctx, scopeOf(actor), access.SessionFilter{
		UserID: &userID, DeviceID: &deviceID, Status: access.StatusActive, Limit: 50,
	})
	if err != nil {
		s.log.Warn("revoke: could not list sessions to terminate", zap.Error(err))
		return
	}
	for i := range live {
		if terr := s.Terminate(ctx, actor, live[i].ID, reason, meta); terr != nil {
			s.log.Warn("revoke: could not terminate session",
				zap.String("session", live[i].ID.String()), zap.Error(terr))
		}
	}
}

// ExpireRequests escalates requests nobody has answered and expires the ones
// that have already had their second chance. Driven by the same worker loop as
// the session reaper.
func (s *Service) ExpireRequests(ctx context.Context) (escalated, expired int, err error) {
	if s.requests == nil {
		return 0, 0, nil
	}
	now := s.clock.Now()
	// Escalate first: a request that has only just run out of time deserves a
	// higher rank before it deserves a grave.
	escalated, err = s.requests.Escalate(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	expired, err = s.requests.ExpireOverdue(ctx, now)
	return escalated, expired, err
}

// notifyApprovers enqueues the "somebody is waiting on you" notification.
func (s *Service) notifyApprovers(ctx context.Context, actor iam.Claims, req *access.Request, emergency bool) {
	if s.notifier == nil {
		return
	}
	event := "approval.requested"
	if emergency {
		event = "approval.emergency"
	}
	s.notifier.Notify(ctx, actor.OrganizationID, event, map[string]any{
		"request_id": req.ID.String(),
		"requester":  actor.Email,
		"device_id":  req.DeviceID.String(),
		"reason":     req.Reason,
		"minutes":    req.RequestedMinutes,
		"level":      req.RequesterLevel,
	})
}

// notifyRequester tells the person who asked what the answer was. Without it
// they sit watching a spinner, which is how an approval system gets a reputation
// for being slower than it is.
func (s *Service) notifyRequester(ctx context.Context, req *access.Request, approved bool) {
	if s.notifier == nil {
		return
	}
	event := "approval.denied"
	if approved {
		event = "approval.granted"
	}
	s.notifier.Notify(ctx, req.OrganizationID, event, map[string]any{
		"request_id": req.ID.String(),
		"requester":  req.RequesterEmail,
		"device":     req.DeviceName,
		"status":     string(req.Status),
	})
}
