package analytics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

type fakeStore struct {
	summary Summary
	search  SearchResults
	rows    []AuditRow
	gotF    AuditFilter
}

func (f *fakeStore) Dashboard(ctx context.Context, s Scope) (Summary, error) { return f.summary, nil }
func (f *fakeStore) Search(ctx context.Context, s Scope, q string, limit int) (SearchResults, error) {
	return f.search, nil
}
func (f *fakeStore) ListAudit(ctx context.Context, s Scope, filter AuditFilter) ([]AuditRow, error) {
	f.gotF = filter
	return f.rows, nil
}

func actor() iam.Claims {
	return iam.Claims{OrganizationID: uuid.New(), Email: "a@example.com"}
}

func TestGenerateCSV_Audit(t *testing.T) {
	ts := time.Date(2026, 7, 14, 10, 30, 0, 0, time.UTC)
	store := &fakeStore{rows: []AuditRow{
		{Timestamp: ts, ActorEmail: "op@corp", Action: "device.create", Category: "device",
			TargetType: "device", TargetID: "d-1", IP: "10.0.0.1", Result: "success"},
	}}
	svc := NewService(store)

	data, filename, err := svc.GenerateCSV(context.Background(), actor(), ReportAudit, nil, nil)
	if err != nil {
		t.Fatalf("GenerateCSV: %v", err)
	}
	if filename != "guardrail-audit-report.csv" {
		t.Fatalf("filename = %q", filename)
	}
	out := string(data)
	if !strings.HasPrefix(out, "timestamp,actor,action,category,target_type,target_id,ip,result") {
		t.Fatalf("missing header row: %q", out)
	}
	if !strings.Contains(out, "2026-07-14T10:30:00Z,op@corp,device.create,device,device,d-1,10.0.0.1,success") {
		t.Fatalf("missing data row: %q", out)
	}
}

func TestGenerateCSV_AccessFiltersByAction(t *testing.T) {
	store := &fakeStore{}
	svc := NewService(store)
	if _, _, err := svc.GenerateCSV(context.Background(), actor(), ReportAccess, nil, nil); err != nil {
		t.Fatalf("GenerateCSV: %v", err)
	}
	if store.gotF.Action != "session." {
		t.Fatalf("access report should filter action prefix, got %q", store.gotF.Action)
	}
}

func TestGenerateCSV_UnknownType(t *testing.T) {
	svc := NewService(&fakeStore{})
	if _, _, err := svc.GenerateCSV(context.Background(), actor(), ReportType("bogus"), nil, nil); err == nil {
		t.Fatal("expected error for unknown report type")
	}
}

func TestSearch_DefaultLimit(t *testing.T) {
	store := &fakeStore{search: SearchResults{Users: []Hit{{ID: "u1", Label: "a@b"}}}}
	svc := NewService(store)
	res, err := svc.Search(context.Background(), actor(), "a", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Users) != 1 {
		t.Fatalf("expected 1 user hit, got %d", len(res.Users))
	}
}
