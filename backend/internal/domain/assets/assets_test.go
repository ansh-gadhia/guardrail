package assets

import (
	"testing"

	"github.com/google/uuid"
)

// Recording is an accountability control: who can switch it off is a security
// boundary, not a convenience.
func TestCanSetRecording(t *testing.T) {
	owner := uuid.New()
	other := uuid.New()

	tests := []struct {
		name      string
		createdBy *uuid.UUID
		userID    uuid.UUID
		isSuper   bool
		want      bool
	}{
		{"the person who added the device", &owner, owner, false, true},
		{"a super admin", &owner, other, true, true},
		{"someone else with device:write", &owner, other, false, false},
		// A device whose creator's account was deleted falls to super-admin-only
		// control rather than becoming editable by anyone.
		{"orphaned device, ordinary user", nil, other, false, false},
		{"orphaned device, super admin", nil, other, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Device{ID: uuid.New(), CreatedBy: tc.createdBy}
			if got := d.CanSetRecording(tc.userID, tc.isSuper); got != tc.want {
				t.Errorf("CanSetRecording() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanSetRecording_ZeroUserIDCannotHijackAnOrphan(t *testing.T) {
	// A nil CreatedBy must never compare equal to a caller's (zero) user id.
	d := &Device{ID: uuid.New(), CreatedBy: nil}
	if d.CanSetRecording(uuid.Nil, false) {
		t.Error("a zero user id was allowed to change an orphaned device's recording policy")
	}
}
