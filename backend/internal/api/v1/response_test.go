package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	appiam "github.com/guardrail/guardrail/internal/app/iam"
	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/domain/vault"
)

// detailFor turns a wrapped sentinel into something worth showing somebody. The
// two failure modes it exists to avoid are a bare "access: invalid", which says
// nothing, and "access: invalid: a reason is required", which leaks a Go error
// string into a user-facing field.
func TestDetailFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped sentinel keeps only the added sentence",
			err:  fmt.Errorf("%w: a reason is required", access.ErrInvalid),
			want: "a reason is required",
		},
		{
			name: "bare sentinel falls back to the written sentence",
			err:  access.ErrInvalid,
			want: "fallback",
		},
		{
			name: "a different error is not mistaken for the sentinel",
			err:  errors.New("something else entirely"),
			want: "fallback",
		},
		{
			name: "sentinel with an empty suffix falls back rather than showing nothing",
			err:  fmt.Errorf("%w: ", access.ErrInvalid),
			want: "fallback",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detailFor(tc.err, access.ErrInvalid, "fallback"); got != tc.want {
				t.Errorf("detailFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// secretJSON must mark the response uncacheable. no-store specifically: no-cache
// still permits a shared proxy or a service worker to write the credential down
// as long as it revalidates later.
func TestSecretJSONSetsNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	secretJSON(c, http.StatusOK, gin.H{"recovery_codes": []string{"a", "b"}})

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "recovery_codes") {
		t.Errorf("body not written: %s", w.Body.String())
	}
}

// TestNoSecretEscapesThroughPlainJSON is the guard for the tenth endpoint.
//
// The finding this fixes was not that one handler forgot the header — it was
// that nine did, while two remembered. A per-site rule does not hold, so this
// scans the delivery package itself: any c.JSON whose body names a known
// credential field is a site that skipped secretJSON. Add a new secret-bearing
// response and this fails until it goes through the helper.
func TestNoSecretEscapesThroughPlainJSON(t *testing.T) {
	// Field names that are, or directly yield, a credential. "token" alone is
	// absent on purpose: it appears in non-secret contexts such as token IDs.
	secretKeys := []string{
		`"password"`, `"recovery_codes"`, `"provisioning_uri"`,
		`"mfa_token"`, `"access_token"`, `AccessToken:`,
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		for _, call := range callsTo(text, "c.JSON(") {
			for _, key := range secretKeys {
				if strings.Contains(call.body, key) {
					t.Errorf("%s:%d writes %s through c.JSON — use secretJSON so the "+
						"response is marked no-store", f, call.line, key)
				}
			}
		}
	}
}

type jsonCall struct {
	line int
	body string
}

// callsTo extracts each invocation of fn, spanning exactly to its balanced
// closing paren.
//
// A fixed line-count window was the obvious approach and it was wrong: it read
// past the end of short calls into whatever followed, and reported
// admin_handlers.go's {"coverage": ...} response as leaking a password because
// a resetPasswordRequest type happened to be declared three lines below. A
// guard that cries wolf gets deleted, so it counts parens.
func callsTo(src, fn string) []jsonCall {
	var out []jsonCall
	for i := 0; ; {
		j := strings.Index(src[i:], fn)
		if j < 0 {
			return out
		}
		start := i + j
		depth, end := 0, start
		for k := start + len(fn) - 1; k < len(src); k++ {
			switch src[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				end = k
				break
			}
		}
		if end <= start {
			end = len(src) - 1
		}
		out = append(out, jsonCall{
			line: strings.Count(src[:start], "\n") + 1,
			body: src[start : end+1],
		})
		i = end + 1
	}
}

// rowError is the bulk-import failure renderer. The property under test is that
// an unrecognised error says nothing about itself: bulk import is the highest
// volume credential intake in the system (500 secrets per request) and used to
// return err.Error() straight into the response body.
func TestRowErrorNeverEchoesAnUnknownError(t *testing.T) {
	// Stand-in for any future error that wraps its input. If this string can
	// reach the caller, so can a secret.
	leaky := fmt.Errorf("vault: seal failed for secret %q on host %s", "hunter2", "10.0.0.1")

	got := rowError(leaky)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("rowError echoed the wrapped value: %q", got)
	}
	if strings.Contains(got, "10.0.0.1") {
		t.Errorf("rowError echoed wrapped context: %q", got)
	}
	if got != "could not be imported" {
		t.Errorf("rowError(unknown) = %q, want the fixed fallback", got)
	}
}

func TestRowErrorKeepsMessagesWrittenForPeople(t *testing.T) {
	// The three import sentinels are showable: their text is the whole point,
	// and losing it would make a failed row unfixable.
	for _, err := range []error{errInvalidUser, errNoSuchUser, errLookupTruncated} {
		if got := rowError(err); got != err.Error() {
			t.Errorf("rowError(%v) = %q, want the sentinel's own text", err, got)
		}
	}

	// Wrapped, it still comes through — errors.As, not equality.
	wrapped := fmt.Errorf("importing row 4: %w", errNoSuchUser)
	if got := rowError(wrapped); got != errNoSuchUser.Error() {
		t.Errorf("rowError(wrapped) = %q, want %q", got, errNoSuchUser.Error())
	}
}

func TestRowErrorMapsDomainSentinels(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{vault.ErrNotFound, "not found"},
		{vault.ErrSecretRequired, "a password or secret is required"},
		{iam.ErrConflict, "already exists"},
	}
	for _, c := range cases {
		if got := rowError(c.err); got != c.want {
			t.Errorf("rowError(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// The browser enforces the console's idle limit, and it takes the number from
// here. A response that dropped it would switch the idle sign-out off without
// anything else noticing — the console treats an absent limit as "none".
func TestTokenResponseCarriesTheIdleLimit(t *testing.T) {
	body := newTokenResponse(&appiam.TokenPair{
		AccessToken: "x", AccessExpiresAt: time.Unix(0, 0), IdleTimeout: 30 * time.Minute,
	})
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["idle_timeout_seconds"] != float64(1800) {
		t.Fatalf("idle_timeout_seconds = %v, want 1800", got["idle_timeout_seconds"])
	}
}
