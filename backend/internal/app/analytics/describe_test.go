package analytics

import "testing"

// Real event shapes, taken from a running deployment's audit log, and what a
// reviewer should read for each.
func TestPresent_SaysWhatHappened(t *testing.T) {
	cases := []struct {
		name                      string
		row                       AuditRow
		title, note, kind, target string
		self                      bool
	}{
		{
			name:  "opening a session names the machine and the protocol",
			row:   AuditRow{Action: "session.start", Result: "success", TargetType: "device", TargetLabel: "MyUbuntuServerDLP", Protocol: "ssh"},
			title: "Opened an SSH session", kind: "Device", target: "MyUbuntuServerDLP",
		},
		{
			name: "a credential used inside a session says which machine it signed in to",
			row: AuditRow{Action: "credential.use", Result: "success", TargetType: "credential", TargetLabel: "ubuntu-root",
				Protocol: "ssh", SessionDevice: "MyUbuntuServerDLP", Detail: map[string]any{"account": "soc"}},
			title: "Signed in to MyUbuntuServerDLP", note: "As soc, over SSH", kind: "Credential", target: "ubuntu-root",
		},
		{
			name:  "a failed sign-in says why, and is about the account that tried",
			row:   AuditRow{Action: "auth.login", Result: "failure", ActorEmail: "a@x.io", TargetType: "user", Detail: map[string]any{"reason": "bad_password"}},
			title: "Sign-in failed", note: "Wrong password", kind: "User", target: "a@x.io", self: true,
		},
		{
			name:  "a sign-in by a since-deleted account still names it",
			row:   AuditRow{Action: "auth.login", Result: "success", ActorEmail: "gone@x.io", TargetType: "user", TargetID: "8655d9a4-f5f5-4462-aa12-34ab593db751"},
			title: "Signed in", kind: "User", target: "gone@x.io", self: true,
		},
		{
			name:  "the password step of a two-factor sign-in is not a sign-in",
			row:   AuditRow{Action: "auth.login", Result: "success", ActorEmail: "a@x.io", Detail: map[string]any{"reason": "mfa_challenge"}},
			title: "Password accepted", note: "A two-factor code was asked for next", kind: "User", target: "a@x.io", self: true,
		},
		{
			name: "ending somebody's sign-in names them, from the detail",
			row: AuditRow{Action: "auth.session_revoke", Result: "success", ActorEmail: "admin@x.io",
				Detail: map[string]any{"target_user": "b1defd5f-fe37-4e10-baf2-b9a946b905f1"},
				Refs:   map[string]string{"b1defd5f-fe37-4e10-baf2-b9a946b905f1": "ansh@x.io"}},
			title: "Ended a sign-in", kind: "User", target: "ansh@x.io",
		},
		{
			name:  "an idle sign-out says how long",
			row:   AuditRow{Action: "auth.session_expired", Result: "success", ActorEmail: "a@x.io", Detail: map[string]any{"reason": "idle", "idle_minutes": float64(30)}},
			title: "Signed out after inactivity", note: "No activity for 30 minutes", kind: "User", target: "a@x.io", self: true,
		},
		{
			name: "an idle sign-out done by GuardRail names whose sign-in it ended",
			// As stored: the account's id in actor_id, no actor email, so the
			// store's own comparison already says "the actor's own account".
			row: AuditRow{Action: "auth.session_expired", Result: "success", TargetType: "user", TargetLabel: "admin@x.io",
				ActorID: "b1defd5f-fe37-4e10-baf2-b9a946b905f1", TargetIsActor: true,
				Detail: map[string]any{"reason": "idle", "idle_minutes": float64(30)}},
			title: "Signed out after inactivity", note: "No activity for 30 minutes", kind: "User", target: "admin@x.io",
		},
		{
			name: "a recording removed by retention is about that recording",
			row: AuditRow{Action: "recording.purged", Result: "success", TargetType: "session", SessionDevice: "MyUbuntuServerDLP",
				Detail: map[string]any{"size_bytes": float64(757572), "retained_to": "2026-09-24T06:00:00Z"}},
			title: "Recording removed by retention", note: "Kept until 24 Sep 2026, 739 KB", kind: "Recording", target: "MyUbuntuServerDLP",
		},
		{
			name:  "an approval says who it was for",
			row:   AuditRow{Action: "approval.granted", Result: "success", TargetType: "device", TargetLabel: "Home Router", Detail: map[string]any{"requester": "ansh@x.io", "approvals": float64(1), "needed": float64(1)}},
			title: "Approved access", note: "For ansh@x.io", kind: "Device", target: "Home Router",
		},
		{
			name:  "a setting change names the setting",
			row:   AuditRow{Action: "settings.recording_retention", Result: "success", Detail: map[string]any{"from_days": float64(90), "to_days": float64(45)}},
			title: "Changed how long recordings are kept", note: "90 → 45 days", kind: "Setting", target: "Recording retention",
		},
		{
			name:  "an action nobody has described yet still reads as words",
			row:   AuditRow{Action: "device.some_new_thing", Result: "failure"},
			title: "Some new thing (failed)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.row
			present(&r)
			if r.Title != c.title || r.Note != c.note || r.TargetKind != c.kind || r.TargetLabel != c.target || r.TargetIsActor != c.self {
				t.Fatalf("got %q / %q / %q %q self=%v\nwant %q / %q / %q %q self=%v",
					r.Title, r.Note, r.TargetKind, r.TargetLabel, r.TargetIsActor,
					c.title, c.note, c.kind, c.target, c.self)
			}
		})
	}
}

// Every action lands in exactly the group whose filter selects it, so choosing
// a group in the console never hides an event that is labelled with it.
func TestGroups_AgreeWithTheirFilters(t *testing.T) {
	actions := []string{"auth.login", "mfa.enroll", "approval.granted", "access.denied", "session.start",
		"credential.use", "credential.rotate", "recording.purged", "device.create", "user.create",
		"team.add_member", "settings.branding", "apitoken.create", "test.chain"}
	for _, a := range actions {
		g := groupOf(a)
		include, exclude, ok := GroupPatterns(g)
		if !ok {
			t.Fatalf("%s: group %q has no filter", a, g)
		}
		if len(include) > 0 && !likeAny(a, include) || likeAny(a, exclude) {
			t.Errorf("%s is labelled %q but that group's filter does not select it", a, g)
		}
	}
}

func likeAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if len(p) > 0 && p[len(p)-1] == '%' {
			if len(s) >= len(p)-1 && s[:len(p)-1] == p[:len(p)-1] {
				return true
			}
		} else if s == p {
			return true
		}
	}
	return false
}
