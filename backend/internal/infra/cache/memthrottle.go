package cache

import (
	"sync"
	"time"
)

// memThrottle is a fixed-window counter held in this process, used when Redis
// cannot answer.
//
// # WHY IT EXISTS
//
// The Redis throttle failed OPEN on any cache error, which meant a Redis outage
// removed per-(ip,email) rate limiting entirely. Account lockout survives that —
// failed_login_count and locked_until live in Postgres — so an attacker still
// got stopped eventually, but they got unlimited attempt SPEED in the meantime,
// and password spraying across many accounts never trips a per-account lockout
// at all.
//
// Failing CLOSED is not the answer either: it would lock every operator out of
// a privileged-access broker for the duration of a cache outage, which is
// precisely when somebody needs to reach a device.
//
// So the guard degrades instead of disappearing. The window and threshold are
// the same; only the store changes. GuardRail runs one API process, so a
// per-process counter is equivalent to the shared one for a single-node
// deployment, and strictly better than nothing for any other.
//
// # MEMORY IS BOUNDED, DELIBERATELY
//
// The key includes an attacker-chosen email, so an unbounded map here would
// turn a cache outage into a memory-exhaustion vector. Expired entries are
// pruned on write and the map is capped; at the cap the oldest entry is
// evicted. Eviction is safe: the worst an attacker gains by flushing out their
// own counter is a reset, and the Postgres account lockout is still counting
// underneath.
type memThrottle struct {
	mu     sync.Mutex
	hits   map[string]*memHit
	max    int
	window time.Duration
	cap    int
	now    func() time.Time
}

type memHit struct {
	n       int
	expires time.Time
}

// memThrottleCap bounds the number of distinct keys held. Roughly 100 bytes an
// entry, so this is a few megabytes at worst.
const memThrottleCap = 50_000

func newMemThrottle(maxFailures int, window time.Duration) *memThrottle {
	return &memThrottle{
		hits:   make(map[string]*memHit),
		max:    maxFailures,
		window: window,
		cap:    memThrottleCap,
		now:    time.Now,
	}
}

// allow reports whether an attempt may proceed, and the remaining window when
// it may not.
func (m *memThrottle) allow(key string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hits[key]
	now := m.now()
	if !ok || now.After(h.expires) {
		return true, 0
	}
	if h.n >= m.max {
		return false, h.expires.Sub(now)
	}
	return true, 0
}

// fail records a failed attempt, starting the window on the first one.
func (m *memThrottle) fail(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if h, ok := m.hits[key]; ok && now.Before(h.expires) {
		h.n++
		return
	}
	m.pruneLocked(now)
	m.hits[key] = &memHit{n: 1, expires: now.Add(m.window)}
}

// reset clears a key after a successful sign-in.
func (m *memThrottle) reset(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hits, key)
}

// pruneLocked drops expired entries, then evicts the oldest if still at cap.
// Caller holds the lock.
func (m *memThrottle) pruneLocked(now time.Time) {
	if len(m.hits) < m.cap {
		return
	}
	for k, h := range m.hits {
		if now.After(h.expires) {
			delete(m.hits, k)
		}
	}
	if len(m.hits) < m.cap {
		return
	}
	// Still full: every entry is live. Evict the one closest to expiring, which
	// is the one whose window started earliest.
	var oldestKey string
	var oldest time.Time
	for k, h := range m.hits {
		if oldestKey == "" || h.expires.Before(oldest) {
			oldestKey, oldest = k, h.expires
		}
	}
	delete(m.hits, oldestKey)
}

// size reports how many keys are held. For tests and diagnostics.
func (m *memThrottle) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hits)
}
