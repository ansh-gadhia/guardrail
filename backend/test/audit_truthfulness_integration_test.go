//go:build integration

package test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/app/analytics"
	appassets "github.com/guardrail/guardrail/internal/app/assets"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/audit"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// The audit_events CHECK constraint is the gatekeeper for the outcome
// vocabulary, and the recorder swallows its own errors — Record's result is
// discarded at every call site, deliberately, so a failed audit write cannot
// take down the operation it describes. That combination means a value the
// database rejects does not fail loudly: the event simply never appears.
//
// So the migration has to be proven from the outside. Against the pre-0029
// schema this test fails at the insert with a constraint violation, which is
// precisely the failure the shipped code would have hidden.
func TestIntegration_AuditAcceptsAPendingOutcome(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	org := defaultOrgID
	actor := uuid.New()
	marker := "test.pending." + uuid.NewString()[:8]
	if err := postgres.NewAuditRepo(pg).Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &actor, ActorEmail: "audit-probe@guardrail.local",
		Action: marker, Category: audit.CategorySession, Result: audit.ResultPending,
	}); err != nil {
		t.Fatalf("the database refused a pending audit event: %v", err)
	}

	rows, err := postgres.NewAnalyticsRepo(pg).ListAudit(ctx,
		analytics.Scope{OrganizationID: defaultOrgID}, analytics.AuditFilter{Action: marker, Limit: 10})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("read back %d events, want 1", len(rows))
	}
	if rows[0].Result != string(audit.ResultPending) {
		t.Errorf("stored result = %q, want %q", rows[0].Result, audit.ResultPending)
	}
}

// A refused attempt to switch recording off used to be written as
// "device.recording_denied — success". Two things were wrong with that at once:
// filtering the Audit Log for denials never surfaced it, and the row a reviewer
// did happen to see claimed the change had gone through when it had been
// blocked. Recording is evidence, so an attempt to remove it is exactly the row
// that has to be accurate.
func TestIntegration_RefusingToDisableRecordingIsAuditedAsDenied(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	// A real owner row: devices.created_by is a foreign key, so a made-up UUID is
	// rejected before the test can get anywhere near the recording policy.
	suffix := uuid.NewString()[:8]
	ownerUser := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail("rec-owner-" + suffix + "@test.local"),
		Username: "rec-owner-" + suffix, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := postgres.NewUserRepo(pg).Create(ctx,
		domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)}, ownerUser); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	owner := uuid.UUID(ownerUser.ID)
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "rec-" + suffix,
		Host: "rec-" + suffix + ".test", Port: 22, Scheme: "ssh",
		Status: "active", RecordSessions: true, CreatedBy: &owner,
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx,
		domassets.Scope{OrganizationID: defaultOrgID}, dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	svc := appassets.NewService(postgres.NewDeviceRepo(pg), postgres.NewAssetGroupRepo(pg), postgres.NewAuditRepo(pg))
	// Somebody who is neither the owner nor a super admin. They may edit the
	// device; they may not touch its recording policy.
	stranger := domiam.Claims{
		UserID: uuid.New(), OrganizationID: defaultOrgID, Email: "stranger@guardrail.local",
	}
	off := false
	if _, err := svc.UpdateDevice(ctx, stranger, dev.ID, appassets.DeviceInput{
		Name: dev.Name, Host: dev.Host, Port: dev.Port, Scheme: dev.Scheme,
		RecordSessions: &off,
	}); !errors.Is(err, domassets.ErrForbidden) {
		t.Fatalf("switching recording off as a stranger = %v, want ErrForbidden", err)
	}

	rows, err := postgres.NewAnalyticsRepo(pg).ListAudit(ctx,
		analytics.Scope{OrganizationID: defaultOrgID},
		analytics.AuditFilter{Action: "device.recording_denied", TargetID: dev.ID.String(), Limit: 10})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("read back %d device.recording_denied events, want 1", len(rows))
	}
	if rows[0].Result == string(audit.ResultSuccess) {
		t.Error(`a refused attempt to disable recording is logged as "success"`)
	}
	if rows[0].Result != string(audit.ResultDenied) {
		t.Errorf("stored result = %q, want %q", rows[0].Result, audit.ResultDenied)
	}
}
