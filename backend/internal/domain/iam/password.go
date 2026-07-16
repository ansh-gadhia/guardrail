package iam

import (
	"regexp"
	"strings"
	"unicode"
)

// MinPasswordLen is the minimum acceptable local password length.
const MinPasswordLen = 12

// PasswordStrength is a coarse 0–4 score for a password. It is the same scale the
// console's strength meter renders, so what a user is told matches what the
// server enforces.
type PasswordStrength int

const (
	StrengthTooWeak PasswordStrength = iota
	StrengthWeak
	StrengthFair
	StrengthGood
	StrengthStrong
)

// MinPasswordStrength is the weakest password the platform accepts. A PAM
// console holds the keys to every device in the estate, so length alone is not
// enough: a password must also mix character classes, or be long enough that it
// doesn't need to.
const MinPasswordStrength = StrengthGood

// longPasswordLen is the length at which a password is strong on length alone.
// It lets a genuine passphrase through without demanding symbol soup, while
// still rejecting a short-but-decorated password.
const longPasswordLen = 20

// commonPasswords are the shapes that pass a naive complexity check but fall to
// the first page of any wordlist. Deliberately short and high-signal — real
// breach-corpus checking belongs in a dedicated service, not a const.
var commonPasswords = []string{
	"password", "letmein", "welcome", "admin", "administrator",
	"qwerty", "iloveyou", "monkey", "dragon", "sunshine", "princess",
	"guardrail", "changeme", "secret", "master",
}

// leetClass maps a letter to the character class that matches it and its usual
// substitutions. A single normalization pass cannot do this job, because the
// substitutions are ambiguous — "1" stands for both "l" and "i", so "l3tm31n"
// only resolves to "letmein" if "1" is read one way and not the other. Matching
// each word as a pattern sidesteps the ambiguity entirely.
var leetClass = map[rune]string{
	'a': "[a4@]", 'b': "[b8]", 'e': "[e3]", 'g': "[g9]", 'i': "[i1!|]",
	'l': "[l1|]", 'o': "[o0]", 's': "[s5$]", 't': "[t7+]", 'z': "[z2]",
}

// commonPatterns is commonPasswords compiled to leet-tolerant regexes.
var commonPatterns = compileCommon(commonPasswords)

func compileCommon(words []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(words))
	for _, w := range words {
		var b strings.Builder
		b.WriteString("(?i)")
		for _, r := range w {
			if cls, ok := leetClass[r]; ok {
				b.WriteString(cls)
			} else {
				b.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		out = append(out, regexp.MustCompile(b.String()))
	}
	return out
}

// ScorePassword rates a password 0–4 on the same rubric the console meter shows:
// a point each for reaching 8 characters, the minimum length, and passphrase
// length; a point for mixing lower/upper/digit; and a point for a symbol.
//
// A password built around a common word scores TooWeak no matter how it is
// decorated, because "Passw0rd!" satisfies every mechanical rule and is still
// guessed instantly.
func ScorePassword(pw string) PasswordStrength {
	if containsCommon(pw) {
		return StrengthTooWeak
	}
	score := 0
	if len(pw) >= 8 {
		score++
	}
	if len(pw) >= MinPasswordLen {
		score++
	}
	if len(pw) >= longPasswordLen {
		score++
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if lower && upper && digit {
		score++
	}
	if symbol {
		score++
	}
	if score > int(StrengthStrong) {
		score = int(StrengthStrong)
	}
	return PasswordStrength(score)
}

// containsCommon reports whether the password is built around a common word,
// tolerating case and leet substitutions.
func containsCommon(pw string) bool {
	for _, re := range commonPatterns {
		if re.MatchString(pw) {
			return true
		}
	}
	return false
}

// ValidatePassword enforces the platform password policy. It returns
// ErrPasswordPolicy when the password is too short or too weak, so every caller
// that sets a password — user creation, self-service change, and the forced
// first-login change — applies one rule rather than each inventing its own.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return ErrPasswordPolicy
	}
	if ScorePassword(pw) < MinPasswordStrength {
		return ErrPasswordPolicy
	}
	return nil
}
