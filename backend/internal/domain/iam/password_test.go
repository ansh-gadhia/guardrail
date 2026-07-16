package iam

import "testing"

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"strong passphrase with symbol", "Tr0ubador&Horse", true},
		{"long mixed with symbol", "Xk7#mQp2!vRn9", true},
		{"exactly minimum length, mixed, symbol", "Ab3!efghijkl", true},
		{"too short even if complex", "Ab3!efgh", false},
		{"long but all lowercase", "abcdefghijklmnop", false},
		{"empty", "", false},
		// The point of scoring over counting: these clear every mechanical rule
		// and are still the first thing an attacker tries.
		{"decorated common word", "Passw0rd!123", false},
		{"product name as password", "GuardRail2026!", false},
		{"leet common word", "L3tm31n!2026", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.pw)
			if tc.ok && err != nil {
				t.Errorf("ValidatePassword(%q) = %v, want accepted", tc.pw, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("ValidatePassword(%q) = accepted, want rejected", tc.pw)
			}
		})
	}
}

func TestScorePassword_IsMonotonicWithComplexity(t *testing.T) {
	// Each step adds one property, so the score must not go down.
	steps := []string{"abcdefgh", "abcdefghijkl", "Abcdefghijk1", "Abcdefghijk1!"}
	prev := PasswordStrength(-1)
	for _, pw := range steps {
		got := ScorePassword(pw)
		if got < prev {
			t.Errorf("ScorePassword(%q) = %d, dropped below the previous step's %d", pw, got, prev)
		}
		prev = got
	}
	if prev != StrengthStrong {
		t.Errorf("fully complex password scored %d, want %d", prev, StrengthStrong)
	}
}

func TestScorePassword_CommonWordIsAlwaysTooWeak(t *testing.T) {
	// A common word must not be rescued by decoration.
	for _, pw := range []string{"password", "Password123!", "p@$$w0rd!!!", "MyAdminSecret1!"} {
		if got := ScorePassword(pw); got != StrengthTooWeak {
			t.Errorf("ScorePassword(%q) = %d, want %d — it is built on a wordlist entry", pw, got, StrengthTooWeak)
		}
	}
}
