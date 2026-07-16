//go:build integration

package test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/app/analytics"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// TestIntegration_AnalyticsDashboardSearchAudit exercises the read-model store
// against the live database: dashboard aggregates, global search, and the audit
// query all run under RLS scoped to the seeded default organization.
func TestIntegration_AnalyticsDashboardSearchAudit(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	scope := analytics.Scope{OrganizationID: defaultOrgID}
	repo := postgres.NewAnalyticsRepo(pg)

	// Seed a uniquely-named device so search can find it deterministically.
	marker := "grsearch" + uuid.NewString()[:8]
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: marker,
		Host: "10.9.9." + uuid.NewString()[:2], Port: 443, Scheme: "https", VerifyTLS: true,
		Vendor: "Cisco", DeviceType: "switch", Status: "active",
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx, domassets.Scope{OrganizationID: defaultOrgID}, dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Dashboard: device count must be >= 1 now.
	sum, err := repo.Dashboard(ctx, scope)
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	if sum.Devices < 1 {
		t.Fatalf("expected at least one device, got %d", sum.Devices)
	}
	if sum.TopDevices == nil || sum.RecentActivity == nil {
		t.Fatal("top devices / recent activity slices must be non-nil")
	}

	// Search: the marker device must surface under devices.
	res, err := repo.Search(ctx, scope, marker, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	found := false
	for _, h := range res.Devices {
		if h.ID == dev.ID.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("search did not return seeded device %q; got %+v", marker, res.Devices)
	}

	// Audit query: filtering must not error and returns a bounded, ordered set.
	rows, err := repo.ListAudit(ctx, scope, analytics.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].Timestamp.After(rows[i-1].Timestamp) {
			t.Fatal("audit rows are not ordered newest-first")
		}
	}
}
