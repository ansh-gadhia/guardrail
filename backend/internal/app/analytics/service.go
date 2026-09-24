// Package analytics is the read-model application layer: dashboard aggregates,
// global search, audit querying, and report generation (CSV). It depends on a
// single Store port implemented by the persistence layer.
package analytics

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Scope is the tenant scope for analytics reads.
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}

func scopeOf(a iam.Claims) Scope {
	return Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

// Summary is the dashboard aggregate.
type Summary struct {
	Devices         int            `json:"devices"`
	ActiveSessions  int            `json:"active_sessions"`
	Users           int            `json:"users"`
	FailedLogins24h int            `json:"failed_logins_24h"`
	TopDevices      []DeviceCount  `json:"top_devices"`
	RecentActivity  []ActivityItem `json:"recent_activity"`
	// AuditVisible says the two fields read from the audit log — the activity
	// feed and the failed-login count — are filled in for this viewer. When it
	// is false they are withheld, not zero: an empty feed and "0 failed
	// logins" would tell somebody without the right to know that all is well.
	AuditVisible bool `json:"audit_visible"`
}

// auditReadPerm is what reading the audit log takes, on the audit page and on
// the dashboard alike.
const auditReadPerm = "log:read"

// DeviceCount is a device with its session count (for "top devices").
type DeviceCount struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Sessions int    `json:"sessions"`
}

// ActivityItem is a recent audit line for the dashboard feed.
type ActivityItem struct {
	Timestamp time.Time `json:"ts"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	// The event in words, as the audit log shows it (see describe.go).
	Title         string `json:"title,omitempty"`
	Note          string `json:"note,omitempty"`
	Group         string `json:"group,omitempty"`
	Target        string `json:"target,omitempty"`
	TargetKind    string `json:"target_kind,omitempty"`
	TargetIsActor bool   `json:"target_is_actor,omitempty"`
}

// SearchResults groups global-search hits by entity type.
type SearchResults struct {
	Users    []Hit `json:"users"`
	Devices  []Hit `json:"devices"`
	Sessions []Hit `json:"sessions"`
}

// Hit is a single search result.
type Hit struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	// Group is one of Groups' keys: a family of actions, as the console
	// filters by them. Empty means every action.
	Group string
	// Search matches the person, the event code, the source address, and what
	// the event was done to by name — a machine, an account, a credential.
	Search     string
	Action     string
	Actor      string
	Result     string
	TargetType string
	TargetID   string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
	// Oldest first instead of newest first.
	Ascending bool
}

// AuditRow is a projected audit event for listing/reporting.
type AuditRow struct {
	Timestamp  time.Time
	ActorEmail string
	Action     string
	Category   string
	TargetType string
	TargetID   string
	// TargetLabel is the target resolved to the name a person recognises — a
	// device name, a user's email, a credential name. Empty when the target has
	// since been purged, or when the action has no target at all; the console
	// falls back to the id rather than showing nothing.
	TargetLabel string
	// SessionID is the session the event happened inside, when it happened inside
	// one. It is what turns an audit row into something a reviewer can follow:
	// the recording, the timeline and the authorization behind it are all one
	// click away instead of a search on another page.
	SessionID string
	IP        string
	UserAgent string
	Result    string
	// Detail is the structured payload recorded with the event (e.g. the failure
	// reason, a device name, an approval decision). Shape varies by action; the
	// delivery layer passes it through verbatim for inspection.
	Detail map[string]any

	// Read alongside the event by the store, for describing it.
	ActorID       string
	TargetIsActor bool              // the target is the account that acted
	Protocol      string            // of the session the event happened in
	SessionDevice string            // that session's device, by name
	Refs          map[string]string // ids named in Detail, resolved to names

	// What happened, in words (see describe.go).
	Title      string
	Group      string
	Note       string
	TargetKind string
}

// Store is the read port implemented by the persistence layer.
type Store interface {
	Dashboard(ctx context.Context, s Scope) (Summary, error)
	Search(ctx context.Context, s Scope, q string, limit int) (SearchResults, error)
	ListAudit(ctx context.Context, s Scope, f AuditFilter) ([]AuditRow, error)
	// CountAudit is how many events match f, ignoring its paging.
	CountAudit(ctx context.Context, s Scope, f AuditFilter) (int, error)
}

// Service implements the analytics use cases.
type Service struct{ store Store }

// NewService constructs the analytics service.
func NewService(store Store) *Service { return &Service{store: store} }

// Dashboard returns the dashboard summary for the actor's tenant.
//
// Its activity feed is the audit log's newest events, described the same way
// the audit page describes them — the dashboard used to show the raw codes
// ("auth.login · someone") the audit page no longer does. If describing them
// fails the plain feed stands; a dashboard is no place to fail over wording.
func (s *Service) Dashboard(ctx context.Context, actor iam.Claims) (Summary, error) {
	sum, err := s.store.Dashboard(ctx, scopeOf(actor))
	if err != nil {
		return sum, err
	}
	// The dashboard needs no permission, and it was handing the audit log's
	// newest events, and its failed-login count, to everybody who could sign in.
	// They are the audit log's to show: same permission as the audit page.
	if !actor.Has(auditReadPerm) {
		sum.RecentActivity = []ActivityItem{}
		sum.FailedLogins24h = 0
		return sum, nil
	}
	sum.AuditVisible = true
	rows, err := s.store.ListAudit(ctx, scopeOf(actor), AuditFilter{Limit: len(sum.RecentActivity)})
	if err != nil || len(rows) == 0 {
		return sum, nil //nolint:nilerr // the undescribed feed is still a feed
	}
	items := make([]ActivityItem, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		present(r)
		items = append(items, ActivityItem{
			Timestamp: r.Timestamp, Actor: r.ActorEmail, Action: r.Action, Result: r.Result,
			Title: r.Title, Note: r.Note, Group: r.Group,
			Target: r.TargetLabel, TargetKind: r.TargetKind, TargetIsActor: r.TargetIsActor,
		})
	}
	sum.RecentActivity = items
	return sum, nil
}

// Search runs a global search across users, devices, and sessions.
func (s *Service) Search(ctx context.Context, actor iam.Claims, q string, limit int) (SearchResults, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.store.Search(ctx, scopeOf(actor), q, limit)
}

// ListAudit returns one page of audit rows matching the filter, each described
// in words, and how many match in all — so the console can page back to the
// very first event rather than stopping at whatever one request returned.
func (s *Service) ListAudit(ctx context.Context, actor iam.Claims, f AuditFilter) ([]AuditRow, int, error) {
	if f.Group != "" {
		if _, _, ok := GroupPatterns(f.Group); !ok {
			return nil, 0, fmt.Errorf("%w: unknown group %q", iam.ErrInvalidInput, f.Group)
		}
	}
	rows, err := s.store.ListAudit(ctx, scopeOf(actor), f)
	if err != nil {
		return nil, 0, err
	}
	for i := range rows {
		present(&rows[i])
	}
	total, err := s.store.CountAudit(ctx, scopeOf(actor), f)
	return rows, total, err
}

// ReportType enumerates supported reports.
type ReportType string

const (
	ReportAudit  ReportType = "audit"
	ReportAccess ReportType = "access"
)

// GenerateCSV produces a CSV report of the given type over an optional window.
func (s *Service) GenerateCSV(ctx context.Context, actor iam.Claims, t ReportType, from, to *time.Time) ([]byte, string, error) {
	f := AuditFilter{From: from, To: to, Limit: 10000}
	switch t {
	case ReportAccess:
		f.Action = "session." // prefix filter handled by store as contains
	case ReportAudit:
	default:
		return nil, "", fmt.Errorf("analytics: unknown report type %q", t)
	}
	rows, err := s.store.ListAudit(ctx, scopeOf(actor), f)
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// The machine columns first, where existing consumers expect them; the
	// words after, so the file reads without a lookup table beside it.
	_ = w.Write([]string{"timestamp", "actor", "action", "category", "target_type", "target_id", "target", "ip", "result", "event", "details"})
	for i := range rows {
		r := &rows[i]
		present(r)
		_ = w.Write([]string{
			r.Timestamp.UTC().Format(time.RFC3339), r.ActorEmail, r.Action, r.Category,
			r.TargetType, r.TargetID, r.TargetLabel, r.IP, r.Result, r.Title, r.Note,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", err
	}
	filename := fmt.Sprintf("guardrail-%s-report.csv", t)
	return buf.Bytes(), filename, nil
}
