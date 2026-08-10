package access

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// viewFixture is one row the fake repository will return, carrying an email so
// the redaction path has something to redact.
func viewFixture() []access.SessionView {
	return []access.SessionView{{
		// DeviceName lives on the Session: it is snapshotted at connect so that
		// deleting the device cannot blank it later.
		Session: access.Session{
			ID: uuid.New(), Protocol: access.ProtocolSSH, Status: access.StatusEnded,
			DeviceName: "core-switch",
		},
		UserEmail: "operator@example.com",
	}}
}

// Holding session:read says you may see that a session happened. Putting a name
// to the operator is a separate grant, so the email must not ride along without
// it — including into the search predicate, which would otherwise let a caller
// probe for addresses they may not read.
func TestListViewRedactsEmailWithoutUserRead(t *testing.T) {
	h := newHarness(opts{})
	h.sessions.views = viewFixture()
	h.sessions.viewTotal = 1

	actor := actorClaims() // no permissions at all
	views, total, err := h.svc.ListView(context.Background(), actor, access.SessionFilter{Search: "oper"})
	if err != nil {
		t.Fatalf("ListView: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if views[0].UserEmail != "" {
		t.Errorf("email leaked without user:read: %q", views[0].UserEmail)
	}
	if h.sessions.lastFilter.SearchEmail {
		t.Error("SearchEmail set without user:read — search could probe for addresses")
	}
	// The device name is not gated: the caller can already list devices.
	if views[0].DeviceName != "core-switch" {
		t.Errorf("DeviceName = %q, want core-switch", views[0].DeviceName)
	}
}

func TestListViewKeepsEmailWithUserRead(t *testing.T) {
	h := newHarness(opts{})
	h.sessions.views = viewFixture()
	h.sessions.viewTotal = 1

	actor := actorClaims()
	actor.Permissions = []string{"user:read"}
	views, _, err := h.svc.ListView(context.Background(), actor, access.SessionFilter{Search: "oper"})
	if err != nil {
		t.Fatalf("ListView: %v", err)
	}
	if views[0].UserEmail != "operator@example.com" {
		t.Errorf("UserEmail = %q, want operator@example.com", views[0].UserEmail)
	}
	if !h.sessions.lastFilter.SearchEmail {
		t.Error("SearchEmail not set despite user:read")
	}
}

// A super admin holds every permission implicitly, not through the list.
func TestListViewSuperAdminSeesEmail(t *testing.T) {
	h := newHarness(opts{})
	h.sessions.views = viewFixture()

	actor := actorClaims()
	actor.IsSuperAdmin = true
	views, _, err := h.svc.ListView(context.Background(), actor, access.SessionFilter{})
	if err != nil {
		t.Fatalf("ListView: %v", err)
	}
	if views[0].UserEmail == "" {
		t.Error("super admin should see the operator email")
	}
}

// Paging arguments must reach the repository untouched: the whole point of the
// change is that the database does the paging, so a dropped offset would put the
// console back to reading page one forever.
func TestListViewPassesPagingThrough(t *testing.T) {
	h := newHarness(opts{})
	if _, _, err := h.svc.ListView(context.Background(), actorClaims(), access.SessionFilter{
		Limit: 25, Offset: 50, SortBy: "duration", SortDesc: true,
	}); err != nil {
		t.Fatalf("ListView: %v", err)
	}
	got := h.sessions.lastFilter
	if got.Limit != 25 || got.Offset != 50 {
		t.Errorf("paging = limit %d offset %d, want 25/50", got.Limit, got.Offset)
	}
	if got.SortBy != "duration" || !got.SortDesc {
		t.Errorf("sort = %q desc=%v, want duration/true", got.SortBy, got.SortDesc)
	}
}

func TestStatsReturnsRepositoryCounters(t *testing.T) {
	h := newHarness(opts{})
	h.sessions.stats = access.SessionStats{Total: 4213, Active: 7, Ended: 4206, Devices: 31}

	st, err := h.svc.Stats(context.Background(), actorClaims())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	// Deliberately larger than any page size: these counters exist because the
	// console used to report the size of the slab it had fetched.
	if st.Total != 4213 || st.Active != 7 || st.Ended != 4206 || st.Devices != 31 {
		t.Errorf("stats = %+v, want 4213/7/4206/31", st)
	}
}
