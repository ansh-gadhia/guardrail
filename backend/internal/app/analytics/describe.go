package analytics

import (
	"fmt"
	"strings"
	"time"
)

// Describing audit events.
//
// An audit event is stored as a machine record — auth.login, a target type and
// a UUID, a JSON detail — which is exactly what a verifier needs and nothing a
// reviewer can read. describe turns each one into what happened, in words: a
// title ("Opened an SSH session"), what it was done to (the device, by name),
// and a note that carries the one or two facts that matter (who it was for,
// why it failed, how long the recording was kept). The machine record is left
// untouched and still travels with the row, for the drawer and the export.
//
// The words live here, not in the console, so the CSV an auditor downloads
// says the same thing the screen does.

// Group is one of the families the console filters by.
type Group struct {
	Key   string
	Label string
}

// Groups, in the order the console offers them.
var Groups = []Group{
	{"signin", "Sign-in"},
	{"access", "Access requests"},
	{"sessions", "Sessions"},
	{"recordings", "Recordings"},
	{"devices", "Devices & credentials"},
	{"people", "People & teams"},
	{"settings", "Settings"},
	{"system", "System"},
}

// groupPatterns are the SQL LIKE patterns each group selects. credential.use
// is in Sessions, not Devices: it is the moment a session was signed in to a
// machine, which is what somebody looking at sessions is looking for.
var groupPatterns = map[string][]string{
	"signin":     {"auth.%", "mfa.%"},
	"access":     {"approval.%", "access.%", "grant.%"},
	"sessions":   {"session.%", "credential.use"},
	"recordings": {"recording.%"},
	"devices":    {"device.%", "credential.%"},
	"people":     {"user.%", "team.%", "role.%", "group.%"},
	"settings":   {"settings.%", "org.%", "apitoken.%"},
}

// GroupPatterns returns the LIKE patterns that select a group and those that
// must then be left out. ok is false for an unknown group.
func GroupPatterns(key string) (include, exclude []string, ok bool) {
	switch key {
	case "devices":
		return groupPatterns["devices"], []string{"credential.use"}, true
	case "system":
		// Whatever no other group claims.
		for _, g := range Groups {
			exclude = append(exclude, groupPatterns[g.Key]...)
		}
		return nil, exclude, true
	}
	p, ok := groupPatterns[key]
	return p, nil, ok
}

func groupOf(action string) string {
	if action == "credential.use" {
		return "sessions"
	}
	for _, g := range Groups {
		for _, p := range groupPatterns[g.Key] {
			if strings.HasSuffix(p, "%") && strings.HasPrefix(action, strings.TrimSuffix(p, "%")) || action == p {
				return g.Key
			}
		}
	}
	return "system"
}

var targetKinds = map[string]string{
	"device":     "Device",
	"user":       "User",
	"credential": "Credential",
	"session":    "Session",
	"role":       "Role",
	"group":      "Device group",
	"team":       "Team",
}

// present fills the row's words in from its record.
func present(r *AuditRow) {
	d := detail(r.Detail)
	r.Group = groupOf(r.Action)
	r.TargetKind = targetKinds[r.TargetType]
	if r.TargetLabel == "" && r.TargetType == "session" && r.SessionDevice != "" {
		r.TargetLabel = r.SessionDevice
	}
	failed := r.Result == "failure"
	refused := r.Result == "denied"
	proto := protoName(r.Protocol)

	// Some actions record what they acted on only in their detail. Give them a
	// target anyway: a row with nothing in that column reads as if nothing was.
	// An account event is about the account that acted — unless GuardRail
	// acted on it (an idle sign-out), when it is about the account named in
	// the target, which is then who the row must name.
	self := func() {
		r.TargetKind = "User"
		if r.ActorEmail == "" {
			// Recorded with the account's id as actor but no actor named: the
			// store's id comparison calls that the account's own act, and it
			// was not — GuardRail did it.
			r.TargetIsActor = false
			return
		}
		if r.TargetLabel != "" && r.TargetLabel != r.ActorEmail {
			return
		}
		r.TargetIsActor = true
		r.TargetLabel = r.ActorEmail
	}
	userRef := func(key string) string { return r.Refs[d.str(key)] }

	switch r.Action {
	// ---- sign-in -------------------------------------------------------------
	case "auth.login", "auth.ldap", "auth.oidc", "auth.sso":
		self()
		via := map[string]string{"auth.ldap": "the directory", "auth.oidc": "single sign-on", "auth.sso": "the SIEM"}[r.Action]
		switch {
		case refused && d.str("reason") == "throttled":
			r.Title, r.Note = "Sign-in blocked", "Too many attempts; this address is paused for a while"
		case failed || refused:
			r.Title = "Sign-in failed"
			r.Note = map[string]string{
				"bad_password":   "Wrong password",
				"unknown_user":   "No account with this email",
				"mfa_bad_code":   "Wrong two-factor code",
				"account_locked": "The account is locked",
				"inactive":       "The account is disabled",
			}[d.str("reason")]
			if r.Note == "" {
				r.Note = human(d.str("reason"))
			}
		case d.str("reason") == "mfa_challenge":
			r.Title, r.Note = "Password accepted", "A two-factor code was asked for next"
		case d.str("reason") == "mfa_totp":
			r.Title, r.Note = "Signed in", "With a two-factor code"
		default:
			r.Title = "Signed in"
			if via != "" {
				r.Note = "Through " + via
			}
		}
	case "auth.logout":
		self()
		r.Title = "Signed out"
	case "auth.session_expired":
		self()
		if d.str("reason") == "idle" {
			r.Title = "Signed out after inactivity"
			if m := d.num("idle_minutes"); m > 0 {
				r.Note = fmt.Sprintf("No activity for %d minutes", m)
			}
		} else {
			r.Title, r.Note = "Signed out at the end of the sign-in", "It reached the longest a sign-in may last"
		}
	case "auth.session_revoke":
		r.Title = "Ended a sign-in"
		if u := userRef("target_user"); u != "" {
			r.TargetKind, r.TargetLabel = "User", u
			r.TargetIsActor = u == r.ActorEmail
		}
	case "auth.refresh":
		self()
		if failed && d.str("reason") == "refresh_reuse" {
			r.Title, r.Note = "Sign-in ended to be safe", "A sign-in token was presented twice"
		} else {
			r.Title = "Sign-in renewed"
		}
	case "auth.password_change":
		self()
		r.Title = "Changed their password"
		if failed {
			r.Title, r.Note = "Password change failed", "The current password was wrong"
		}
	case "auth.network_denied":
		self()
		r.Title, r.Note = "Sign-in blocked", "The address is outside the network policy"
	case "auth.sso.provision":
		r.Title, r.Note = "Account created", "By single sign-on"
	case "auth.sso.reconcile", "auth.sso.resync", "auth.sso.sync":
		r.Title, r.Note = "Account updated", "From the SIEM"
	case "mfa.enroll":
		self()
		r.Title = "Turned on two-factor sign-in"
	case "mfa.enroll.begin":
		self()
		r.Title = "Started setting up two-factor sign-in"
	case "mfa.disable":
		self()
		r.Title = "Turned off two-factor sign-in"
		if failed {
			r.Title, r.Note = "Two-factor sign-in left on", "Wrong two-factor code"
		}
	case "mfa.recovery_regenerate":
		self()
		r.Title = "Made new recovery codes"

	// ---- sessions --------------------------------------------------------------
	case "session.start":
		r.Title = "Opened " + article(proto) + " session"
		if failed || refused {
			r.Title = "Could not open " + article(proto) + " session"
		}
	case "session.end":
		r.Title = "Ended " + article(proto) + " session"
		r.Note = map[string]string{
			"admin_terminate": "Ended by an administrator",
			"idle_timeout":    "Nothing happened in it for too long",
			"window_expired":  "Its access window closed",
			"user":            "Closed by the person using it",
		}[d.str("reason")]
		if refused {
			r.Title, r.Note = "Refused to end a session", d.str("reason")
		} else if r.Note == "" && d.str("reason") != "" {
			r.Note = human(d.str("reason"))
		}
	case "session.observe":
		r.Title = "Watched " + article(proto) + " session live"
		if u := userRef("observed_user_id"); u != "" {
			r.Note = "Used by " + u
		}
		if d.str("mode") == "read-only" {
			r.Note = joinNote(r.Note, "read-only")
		}
	case "session.establish_failed":
		r.Title = "Could not connect"
		r.Note = strings.TrimPrefix(strings.TrimPrefix(d.str("error"), "browser: "), "establish: ")
	case "credential.use":
		r.Title = "Signed in to a machine with a credential"
		if r.SessionDevice != "" {
			r.Title = "Signed in to " + r.SessionDevice
		}
		r.Note = joinNote(accountNote(d.str("account")), protoNote(proto))

	// ---- access requests ----------------------------------------------------------
	case "approval.requested":
		r.Title = "Requested access"
		if refused {
			r.Title = "Access request declined"
		}
		if q := d.str("reason"); q != "" {
			r.Note = "“" + q + "”"
		}
	case "approval.granted":
		r.Title = "Approved access"
		r.Note = forNote(d.str("requester"))
		if n, of := d.num("approvals"), d.num("needed"); of > 1 {
			r.Note = joinNote(r.Note, fmt.Sprintf("%d of %d approvals", n, of))
		}
	case "approval.denied":
		r.Title, r.Note = "Denied access", forNote(d.str("requester"))
	case "approval.reviewed":
		r.Title, r.Note = "Reviewed an access request", forNote(d.str("requester"))
	case "approval.emergency":
		r.Title, r.Note = "Used break-glass access", quoted(d.str("reason"))
	case "approval.emergency_refused":
		r.Title = "Break-glass access refused"
	case "access.granted":
		r.Title = "Access allowed"
		// #nosec G101 -- sentences describing an approval gate, not credentials.
		r.Note = map[string]string{
			"approved":       "The request was approved",
			"standing_grant": "Standing access",
			"device_owner":   "Owner of the device",
			"bypass":         "No approval required",
			"emergency":      "Break-glass",
		}[d.str("gate")]
	case "access.denied":
		r.Title = "Access refused"
		r.Note = map[string]string{
			"recording_unavailable": "Recording could not start, and this device requires it",
		}[d.str("reason")]
		if r.Note == "" {
			r.Note = human(d.str("reason"))
		}
	case "grant.revoked":
		r.Title = "Revoked standing access"

	// ---- recordings -----------------------------------------------------------------
	case "recording.view":
		r.Title = "Played a recording"
	case "recording.delete":
		r.Title, r.Note = "Deleted a recording", size(d.num("size_bytes"))
	case "recording.purged":
		r.Title = "Recording removed by retention"
		if t, err := time.Parse(time.RFC3339, d.str("retained_to")); err == nil {
			r.Note = "Kept until " + t.Format("2 Jan 2006")
		}
		r.Note = joinNote(r.Note, size(d.num("size_bytes")))
	}

	if r.Title == "" {
		r.Title = catalogue[r.Action]
	}
	if r.Title == "" {
		r.Title = human(r.Action[strings.Index(r.Action, ".")+1:])
		switch {
		case failed:
			r.Title += " (failed)"
		case refused:
			r.Title += " (refused)"
		}
	}
	if r.Note == "" {
		r.Note = notes(r, d)
	}
	// The recording of a session is what those rows act on.
	if strings.HasPrefix(r.Action, "recording.") && r.TargetType == "session" {
		r.TargetKind = "Recording"
	}
}

// catalogue names the actions whose title needs nothing from their detail.
//
// #nosec G101 -- event names and their wording ("credential.rotate", "Rotated a
// credential"); no secret is anywhere near this table.
var catalogue = map[string]string{
	"device.create":                "Added a device",
	"device.update":                "Changed a device",
	"device.delete":                "Removed a device",
	"device.recording_denied":      "Refused to turn off recording",
	"credential.create":            "Added a credential",
	"credential.delete":            "Deleted a credential",
	"credential.rotate":            "Rotated a credential",
	"credential.purge":             "Purged a credential",
	"user.create":                  "Created a user",
	"user.delete":                  "Deleted a user",
	"user.provision":               "Provisioned a user",
	"user.bootstrap":               "Created the first administrator",
	"user.assign_roles":            "Changed a user's roles",
	"user.reset_password":          "Reset a password",
	"user.protected_denied":        "Change to a protected account refused",
	"team.create":                  "Created a team",
	"team.update":                  "Changed a team",
	"team.delete":                  "Deleted a team",
	"team.add_member":              "Added a team member",
	"team.remove_member":           "Removed a team member",
	"team.set_members":             "Changed a team's members",
	"team.set_grants":              "Changed what a team can reach",
	"group.create":                 "Created a device group",
	"group.add_member":             "Added a device to a group",
	"group.remove_member":          "Removed a device from a group",
	"role.approval_level":          "Changed a role's approval level",
	"role.set_device_access":       "Changed a role's device access",
	"org.create":                   "Created an organization",
	"apitoken.create":              "Created an API token",
	"apitoken.revoke":              "Revoked an API token",
	"settings.branding":            "Changed the branding",
	"settings.network_policy":      "Changed the network policy",
	"settings.recording_retention": "Changed how long recordings are kept",
}

// notes carries the fact worth reading for the actions in the catalogue.
func notes(r *AuditRow, d detail) string {
	switch {
	case r.Action == "user.assign_roles":
		if n := d.num("role_count"); n >= 0 && d.has("role_count") {
			return plural(n, "role", "roles") + " now"
		}
	case r.Action == "user.reset_password":
		if r.TargetLabel == "" {
			r.TargetKind, r.TargetLabel = "User", d.str("target")
		}
		if d.str("generated") == "true" {
			return "A temporary password was issued"
		}
	case r.Action == "user.protected_denied":
		if r.TargetLabel == "" {
			r.TargetKind, r.TargetLabel = "User", d.str("target")
		}
		if a := d.str("attempted"); a != "" {
			return "Tried: " + a
		}
	case r.Action == "team.add_member", r.Action == "team.remove_member":
		return r.Refs[d.str("user_id")]
	case r.Action == "team.create", r.Action == "team.delete":
		if r.TargetLabel == "" {
			r.TargetLabel = d.str("name")
		}
	case strings.HasPrefix(r.Action, "apitoken."):
		r.TargetKind = "API token"
		if r.TargetLabel == "" {
			r.TargetLabel = d.str("name")
		}
		if r.TargetLabel == "" {
			r.TargetLabel = r.Refs[d.str("token_id")]
		}
		if s := d.strs("scopes"); len(s) > 0 {
			return "Can " + strings.Join(s, ", ")
		}
	case r.Action == "settings.branding":
		r.TargetKind, r.TargetLabel = "Setting", "Branding"
		if n := d.str("to_name"); n != "" {
			return "Client name: " + n
		}
	case r.Action == "settings.network_policy":
		r.TargetKind, r.TargetLabel = "Setting", "Network policy"
		return joinNote(listNote("allowlist", d.str("allowlist_enabled") == "true", len(d.strs("allowlist_entries"))),
			listNote("blocklist", d.str("blocklist_enabled") == "true", len(d.strs("blocklist_entries"))))
	case r.Action == "settings.recording_retention":
		r.TargetKind, r.TargetLabel = "Setting", "Recording retention"
		if d.has("from_days") && d.has("to_days") {
			return fmt.Sprintf("%d → %d days", d.num("from_days"), d.num("to_days"))
		}
	case strings.HasPrefix(r.Action, "test."):
		r.Title = "Test event"
		return "Written by an automated test"
	}
	return ""
}

// ---- small helpers -------------------------------------------------------------------

type detail map[string]any

func (d detail) has(k string) bool { _, ok := d[k]; return ok }

func (d detail) str(k string) string {
	switch v := d[k].(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%g", v)
	}
	return ""
}

func (d detail) num(k string) int {
	if v, ok := d[k].(float64); ok {
		return int(v)
	}
	return 0
}

func (d detail) strs(k string) []string {
	arr, _ := d[k].([]any)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func protoName(p string) string {
	switch strings.ToLower(p) {
	case "ssh":
		return "SSH"
	case "rdp":
		return "RDP"
	case "vnc":
		return "VNC"
	case "telnet":
		return "Telnet"
	case "http", "https", "web", "browser":
		return "web"
	}
	return ""
}

// article puts "a" or "an" before a protocol said aloud: an SSH, an RDP, a VNC.
func article(proto string) string {
	switch proto {
	case "":
		return "a"
	case "SSH", "RDP":
		return "an " + proto
	}
	return "a " + proto
}

func protoNote(proto string) string {
	if proto == "" || proto == "web" {
		return ""
	}
	return "over " + proto
}

func accountNote(a string) string {
	if a == "" {
		return ""
	}
	return "as " + a
}

func forNote(who string) string {
	if who == "" {
		return ""
	}
	return "For " + who
}

func quoted(s string) string {
	if s == "" {
		return ""
	}
	return "“" + s + "”"
}

func listNote(name string, on bool, n int) string {
	if !on {
		return name + " off"
	}
	return fmt.Sprintf("%s on, %s", name, plural(n, "entry", "entries"))
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return capital(b)
	case b == "":
		return capital(a)
	}
	return capital(a) + ", " + b
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func size(b int) string {
	switch {
	case b <= 0:
		return ""
	case b < 1<<10:
		return fmt.Sprintf("%d bytes", b)
	case b < 1<<20:
		return fmt.Sprintf("%d KB", b>>10)
	case b < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
}

// human turns a code into words: "recording_unavailable" → "Recording unavailable".
func human(code string) string {
	return capital(strings.NewReplacer("_", " ", ".", " ").Replace(code))
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
