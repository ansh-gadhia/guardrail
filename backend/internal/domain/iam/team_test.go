package iam

import "testing"

// The rank ladder is duplicated in SQL (app_access_rank / app_access_level in
// migration 0034) because the reach query has to order levels inside the
// database. Duplication is the risk this test exists to contain: if the two ever
// disagree, a grant means one thing to the listing filter and another to the
// connect check, and nothing else in the system would notice.
func TestAccessLevelRankLadder(t *testing.T) {
	// The pairs mirror the CASE arms in app_access_rank verbatim.
	want := map[AccessLevel]int{
		AccessManage:  3,
		AccessConnect: 2,
		AccessView:    1,
		AccessNone:    0,
	}
	for level, rank := range want {
		if got := level.Rank(); got != rank {
			t.Errorf("%s.Rank() = %d, want %d (app_access_rank disagrees)", level, got, rank)
		}
		if got := AccessLevelFromRank(rank); got != level {
			t.Errorf("AccessLevelFromRank(%d) = %s, want %s (app_access_level disagrees)", rank, got, level)
		}
	}
	// Anything unrecognised ranks below view, so an unknown string can never be
	// read as more access than the weakest real level.
	if AccessLevel("wheelbarrow").Rank() != 0 {
		t.Error("an unknown level must rank 0")
	}
}

func TestAccessLevelAtLeast(t *testing.T) {
	cases := []struct {
		have, want AccessLevel
		ok         bool
	}{
		{AccessManage, AccessConnect, true},
		{AccessConnect, AccessConnect, true},
		{AccessView, AccessConnect, false}, // the whole point of 'view'
		{AccessNone, AccessView, false},
		{AccessConnect, AccessView, true},
		{AccessManage, AccessManage, true},
		{AccessConnect, AccessManage, false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.want); got != c.ok {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

func TestNormalizeAccessLevel(t *testing.T) {
	// A slice of pairs, not a map: one of the inputs is deliberately padded with
	// whitespace (trimming is part of what this checks), and a map key carrying
	// significant whitespace reads as a typo to both linters and people.
	cases := []struct {
		in   string
		want AccessLevel
	}{
		{"view", AccessView}, {"READ", AccessView}, {" read-only ", AccessView},
		{"connect", AccessConnect}, {"use", AccessConnect},
		{"manage", AccessManage}, {"Write", AccessManage}, {"FULL", AccessManage},
		{"none", AccessNone}, {"", AccessNone},
	}
	for _, c := range cases {
		if got := NormalizeAccessLevel(c.in); got != c.want {
			t.Errorf("NormalizeAccessLevel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Unrecognised input returns "", so a caller rejects it rather than falling
	// back to a level nobody asked for. A typo must not silently grant.
	if got := NormalizeAccessLevel("mange"); got != "" {
		t.Errorf("NormalizeAccessLevel(\"mange\") = %q, want \"\"", got)
	}
}

func TestAccessLevelValid(t *testing.T) {
	for _, l := range []AccessLevel{AccessView, AccessConnect, AccessManage} {
		if !l.Valid() {
			t.Errorf("%s should be storable", l)
		}
	}
	// AccessNone is deliberately not storable: a grant row that grants nothing
	// hides a mistake that a validation error would surface.
	for _, l := range []AccessLevel{AccessNone, "", "admin"} {
		if l.Valid() {
			t.Errorf("%q should not be storable as a grant level", l)
		}
	}
}

func TestTeamValidate(t *testing.T) {
	t.Run("trims and defaults", func(t *testing.T) {
		team := Team{Name: "  IT  ", Description: " kit "}
		if err := team.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if team.Name != "IT" || team.Description != "kit" {
			t.Fatalf("not trimmed: %q / %q", team.Name, team.Description)
		}
		if team.AllDevicesLevel != AccessNone {
			t.Fatalf("blanket grant defaulted to %q, want none", team.AllDevicesLevel)
		}
	})
	t.Run("rejects an empty name", func(t *testing.T) {
		team := Team{Name: "   "}
		if err := team.Validate(); err == nil {
			t.Fatal("a whitespace-only name should be rejected")
		}
	})
	t.Run("rejects an unknown blanket level", func(t *testing.T) {
		team := Team{Name: "IT", AllDevicesLevel: AccessLevel("everything")}
		if err := team.Validate(); err == nil {
			t.Fatal("an unknown blanket level should be rejected")
		}
	})
}

func TestTeamGrantsValidate(t *testing.T) {
	gid := ID{1}
	t.Run("defaults a missing level to connect", func(t *testing.T) {
		g := TeamGrants{Groups: []GroupGrant{{AssetGroupID: gid}}}
		if err := g.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		// Connect is what a grant meant before levels existed, so a client that
		// sends none keeps the behaviour it would have had.
		if g.Groups[0].Level != AccessConnect {
			t.Fatalf("level defaulted to %q, want connect", g.Groups[0].Level)
		}
	})
	t.Run("rejects a duplicate group", func(t *testing.T) {
		g := TeamGrants{Groups: []GroupGrant{
			{AssetGroupID: gid, Level: AccessView},
			{AssetGroupID: gid, Level: AccessManage},
		}}
		// Two levels for one group has no defined answer, and the repository
		// counts rows to detect ids it could not see — a duplicate would make
		// that count lie.
		if err := g.Validate(); err == nil {
			t.Fatal("a duplicated group should be rejected")
		}
	})
	t.Run("rejects a duplicate device type regardless of case", func(t *testing.T) {
		g := TeamGrants{DeviceTypes: []TypeGrant{
			{DeviceType: "firewall", Level: AccessView},
			{DeviceType: "Firewall", Level: AccessManage},
		}}
		if err := g.Validate(); err == nil {
			t.Fatal("a duplicated device type should be rejected")
		}
	})
	t.Run("rejects a blank device type", func(t *testing.T) {
		g := TeamGrants{DeviceTypes: []TypeGrant{{DeviceType: "  "}}}
		if err := g.Validate(); err == nil {
			t.Fatal("a blank device type should be rejected")
		}
	})
	t.Run("rejects an unknown level", func(t *testing.T) {
		g := TeamGrants{Groups: []GroupGrant{{AssetGroupID: gid, Level: AccessLevel("none")}}}
		if err := g.Validate(); err == nil {
			t.Fatal("a grant at level none should be rejected")
		}
	})
}
