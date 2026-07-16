// Package analytics is the read-model application layer: dashboard aggregates,
// global search, audit querying, and report generation (CSV). It depends on a
// single AnalyticsStore port implemented by the persistence layer.
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
}

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
	Action     string
	Actor      string
	Result     string
	TargetType string
	TargetID   string
	From       *time.Time
	To         *time.Time
	Limit      int
}

// AuditRow is a projected audit event for listing/reporting.
type AuditRow struct {
	Timestamp  time.Time
	ActorEmail string
	Action     string
	Category   string
	TargetType string
	TargetID   string
	IP         string
	UserAgent  string
	Result     string
	// Detail is the structured payload recorded with the event (e.g. the failure
	// reason, a device name, an approval decision). Shape varies by action; the
	// delivery layer passes it through verbatim for inspection.
	Detail map[string]any
}

// AnalyticsStore is the read port implemented by the persistence layer.
type AnalyticsStore interface {
	Dashboard(ctx context.Context, s Scope) (Summary, error)
	Search(ctx context.Context, s Scope, q string, limit int) (SearchResults, error)
	ListAudit(ctx context.Context, s Scope, f AuditFilter) ([]AuditRow, error)
}

// Service implements the analytics use cases.
type Service struct{ store AnalyticsStore }

// NewService constructs the analytics service.
func NewService(store AnalyticsStore) *Service { return &Service{store: store} }

// Dashboard returns the dashboard summary for the actor's tenant.
func (s *Service) Dashboard(ctx context.Context, actor iam.Claims) (Summary, error) {
	return s.store.Dashboard(ctx, scopeOf(actor))
}

// Search runs a global search across users, devices, and sessions.
func (s *Service) Search(ctx context.Context, actor iam.Claims, q string, limit int) (SearchResults, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.store.Search(ctx, scopeOf(actor), q, limit)
}

// ListAudit returns audit rows matching the filter.
func (s *Service) ListAudit(ctx context.Context, actor iam.Claims, f AuditFilter) ([]AuditRow, error) {
	return s.store.ListAudit(ctx, scopeOf(actor), f)
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
	_ = w.Write([]string{"timestamp", "actor", "action", "category", "target_type", "target_id", "ip", "result"})
	for _, r := range rows {
		_ = w.Write([]string{
			r.Timestamp.UTC().Format(time.RFC3339), r.ActorEmail, r.Action, r.Category,
			r.TargetType, r.TargetID, r.IP, r.Result,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", err
	}
	filename := fmt.Sprintf("guardrail-%s-report.csv", t)
	return buf.Bytes(), filename, nil
}
