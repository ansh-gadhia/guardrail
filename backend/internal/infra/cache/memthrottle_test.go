package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestMemThrottleBlocksAfterMax(t *testing.T) {
	m := newMemThrottle(3, time.Minute)
	const key = "throttle:login:10.0.0.1:op@corp"

	for i := range 3 {
		if ok, _ := m.allow(key); !ok {
			t.Fatalf("blocked after %d failures, threshold is 3", i)
		}
		m.fail(key)
	}
	ok, retry := m.allow(key)
	if ok {
		t.Fatal("still allowing attempts after the threshold was reached")
	}
	if retry <= 0 || retry > time.Minute {
		t.Errorf("retry-after = %v, want a slice of the window", retry)
	}
}

func TestMemThrottleWindowExpires(t *testing.T) {
	m := newMemThrottle(2, time.Minute)
	now := time.Now()
	m.now = func() time.Time { return now }
	const key = "k"

	m.fail(key)
	m.fail(key)
	if ok, _ := m.allow(key); ok {
		t.Fatal("not blocked at the threshold")
	}

	// Past the window, the counter is spent.
	now = now.Add(time.Minute + time.Second)
	if ok, _ := m.allow(key); !ok {
		t.Fatal("still blocked after the window expired")
	}
}

func TestMemThrottleResetClears(t *testing.T) {
	m := newMemThrottle(1, time.Minute)
	m.fail("k")
	if ok, _ := m.allow("k"); ok {
		t.Fatal("not blocked")
	}
	m.reset("k")
	if ok, _ := m.allow("k"); !ok {
		t.Fatal("reset did not clear the counter")
	}
}

// The key contains an attacker-chosen email, so an unbounded map here would turn
// a cache outage into a memory-exhaustion vector.
func TestMemThrottleMemoryIsBounded(t *testing.T) {
	m := newMemThrottle(5, time.Hour) // long window: nothing expires on its own
	m.cap = 100

	for i := range 1000 {
		m.fail(fmt.Sprintf("throttle:login:10.0.0.1:user%d@corp", i))
	}
	if got := m.size(); got > m.cap {
		t.Fatalf("held %d keys, cap is %d — memory is unbounded", got, m.cap)
	}
}

// Eviction must not let an attacker DoS logins: filling the map evicts entries
// rather than refusing new ones.
func TestMemThrottleEvictionDoesNotBlockNewKeys(t *testing.T) {
	m := newMemThrottle(5, time.Hour)
	m.cap = 50
	for i := range 500 {
		m.fail(fmt.Sprintf("filler%d", i))
	}
	// A fresh operator arriving during the flood is still allowed.
	if ok, _ := m.allow("throttle:login:10.0.0.9:real@corp"); !ok {
		t.Fatal("a new key was blocked because the map was full — that is a login DoS")
	}
}

// Expired entries are reclaimed rather than evicting live ones.
func TestMemThrottlePrunesExpiredFirst(t *testing.T) {
	m := newMemThrottle(5, time.Minute)
	m.cap = 10
	now := time.Now()
	m.now = func() time.Time { return now }

	for i := range 10 {
		m.fail(fmt.Sprintf("old%d", i))
	}
	now = now.Add(2 * time.Minute) // every entry is now expired
	m.fail("fresh")

	if m.size() > m.cap {
		t.Fatalf("held %d keys after pruning, cap is %d", m.size(), m.cap)
	}
	if ok, _ := m.allow("fresh"); !ok {
		t.Fatal("the new key was lost to pruning")
	}
}
