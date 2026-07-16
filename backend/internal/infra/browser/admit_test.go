package browser

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
)

const mib = 1 << 20

func admitGateway(avail func() (uint64, error)) *Gateway {
	g := NewGateway(Config{
		SessionMemoryEstimate: 400 * mib,
		HostReserve:           512 * mib,
	}, Deps{Log: zap.NewNop()})
	g.availMem = avail
	return g
}

func fixedMem(bytes uint64) func() (uint64, error) {
	return func() (uint64, error) { return bytes, nil }
}

func TestAdmitAllowsWhenHeadroomSuffices(t *testing.T) {
	// Exactly the requirement is enough: the check refuses only below it.
	g := admitGateway(fixedMem(912 * mib))
	if err := g.admit(); err != nil {
		t.Errorf("want admit at exactly session+reserve, got %v", err)
	}
}

func TestAdmitRefusesWhenBelowReserve(t *testing.T) {
	// Enough for the session itself, but it would eat into the host reserve —
	// which is the state that ends in an OOM rather than a slow session.
	g := admitGateway(fixedMem(500 * mib))
	if err := g.admit(); !errors.Is(err, access.ErrCapacity) {
		t.Errorf("want ErrCapacity, got %v", err)
	}
}

func TestAdmitRefusesWhenNearlyOut(t *testing.T) {
	g := admitGateway(fixedMem(10 * mib))
	if err := g.admit(); !errors.Is(err, access.ErrCapacity) {
		t.Errorf("want ErrCapacity, got %v", err)
	}
}

// An unmeasurable host must not wedge every recorded session shut. This
// restores the prior (unbounded) behaviour rather than inventing a new failure.
func TestAdmitAllowsWhenMemoryUnmeasurable(t *testing.T) {
	g := admitGateway(func() (uint64, error) { return 0, errors.New("no /proc") })
	if err := g.admit(); err != nil {
		t.Errorf("want admit when memory cannot be read, got %v", err)
	}
}

// Admission must scale with configured cost: a deployment that tells us its
// sessions are cheap should fit more of them in the same memory.
func TestAdmitHonoursConfiguredCost(t *testing.T) {
	g := NewGateway(Config{
		SessionMemoryEstimate: 50 * mib,
		HostReserve:           50 * mib,
	}, Deps{Log: zap.NewNop()})
	g.availMem = fixedMem(150 * mib)
	if err := g.admit(); err != nil {
		t.Errorf("cheap sessions should fit: %v", err)
	}

	g2 := admitGateway(fixedMem(150 * mib)) // default 400+512 MiB
	if err := g2.admit(); !errors.Is(err, access.ErrCapacity) {
		t.Errorf("same memory, expensive sessions should not fit: %v", err)
	}
}

// Defaults must be real values, not zero — a zero requirement would admit
// everything and silently disable the check.
func TestAdmissionDefaultsAreNonZero(t *testing.T) {
	var c Config
	c.defaults()
	if c.SessionMemoryEstimate == 0 || c.HostReserve == 0 {
		t.Fatalf("admission defaults must be set: session=%d reserve=%d",
			c.SessionMemoryEstimate, c.HostReserve)
	}
}
