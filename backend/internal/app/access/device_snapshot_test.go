package access

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// A session records what it connected to, at the time it connected.
//
// The alternative — resolving the name by joining devices at read time — makes
// the audit trail a function of the present rather than a record of the past:
// renaming a firewall retitles last year's sessions, and deleting it leaves
// every session it ever served showing a bare UUID. Both are ways of losing
// evidence without deleting any.
func TestConnectSnapshotsDeviceIdentity(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if len(h.sessions.created) != 1 {
		t.Fatalf("created %d sessions, want 1", len(h.sessions.created))
	}
	got := h.sessions.created[0]

	if got.DeviceName != "edge-firewall" {
		t.Errorf("DeviceName = %q, want edge-firewall", got.DeviceName)
	}
	if got.DeviceType != "firewall" {
		t.Errorf("DeviceType = %q, want firewall", got.DeviceType)
	}
	// host:port as dialled — "which box was that" is the question a reviewer
	// actually asks, and an address survives a rename.
	if got.DeviceAddress != "10.0.0.1:443" {
		t.Errorf("DeviceAddress = %q, want 10.0.0.1:443", got.DeviceAddress)
	}
	// The id is still there, so a reviewer can pivot to the device while it lasts.
	if got.DeviceID == (uuid.UUID{}) {
		t.Error("DeviceID was not recorded")
	}
}
