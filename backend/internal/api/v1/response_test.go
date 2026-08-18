package v1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
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
