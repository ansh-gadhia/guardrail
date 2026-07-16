// Package health probes registered devices for liveness so the console can show
// whether a device is actually reachable, rather than implying every registered
// device is up. It is a read-only observer: it never mutates the inventory.
package health

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/infra/proxy"
)

// Config holds poller policy.
type Config struct {
	// Interval is how often the whole inventory is swept.
	Interval time.Duration
	// Timeout bounds a single device probe.
	Timeout time.Duration
	// Concurrency caps simultaneous probes so a large inventory doesn't open a
	// socket per device at once.
	Concurrency int
}

// DefaultConfig returns sensible poller defaults.
func DefaultConfig() Config {
	return Config{Interval: 60 * time.Second, Timeout: 5 * time.Second, Concurrency: 16}
}

// Service polls device liveness.
type Service struct {
	repo assets.HealthRepository
	log  *zap.Logger
	cfg  Config
}

// NewService constructs the health poller.
func NewService(repo assets.HealthRepository, log *zap.Logger, cfg Config) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultConfig().Interval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConfig().Concurrency
	}
	return &Service{repo: repo, log: log, cfg: cfg}
}

// Run sweeps the inventory on a ticker until ctx is done. It probes once
// immediately so a freshly started server doesn't show every device as unknown
// for a full interval.
func (s *Service) Run(ctx context.Context) {
	s.SweepOnce(ctx)
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SweepOnce(ctx)
		}
	}
}

// SweepOnce probes every active device once, bounded by the configured
// concurrency. Exported so a test (or an operator-triggered refresh) can drive a
// single sweep without the ticker.
func (s *Service) SweepOnce(ctx context.Context) {
	targets, err := s.repo.ListProbeTargets(ctx)
	if err != nil {
		s.log.Warn("health sweep: could not list devices", zap.Error(err))
		return
	}
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(t assets.ProbeTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			h := s.probe(ctx, t)
			if err := s.repo.Upsert(ctx, t.DeviceID, h); err != nil {
				s.log.Warn("health sweep: could not record result",
					zap.String("device_id", t.DeviceID.String()), zap.Error(err))
			}
		}(t)
	}
	wg.Wait()
}

// probe checks one device is reachable, by whatever means suits its protocol.
//
// For a web device, any HTTP response — including 401 or 403 — means it is up and
// serving: a management UI that challenges an unauthenticated request is
// precisely a healthy one. Only a transport failure (refused, timeout, DNS, TLS
// handshake) counts as offline.
func (s *Service) probe(ctx context.Context, t assets.ProbeTarget) assets.Health {
	now := time.Now().UTC()
	h := assets.Health{CheckedAt: &now}

	// The poller reaches internal networks on a timer with no user in the loop,
	// so it honours the same egress policy as the proxy.
	if err := proxy.GuardSSRF(t.Host); err != nil {
		h.Status = assets.HealthUnknown
		h.LastError = err.Error()
		h.ConsecutiveFailures = t.ConsecutiveFailures
		return h
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	// An SSH, RDP or VNC device has no URL to fetch, and asking an HTTP client to
	// fetch one produced `Head "ssh://host:22": unsupported protocol scheme "ssh"`
	// — reported as OFFLINE. So every terminal and desktop device in the estate
	// showed as down while being perfectly reachable, and the one signal an
	// operator uses to tell "the box is gone" from "my credential is wrong" said
	// the opposite of the truth.
	if !assets.IsWebScheme(t.Scheme) {
		return s.probeTCP(ctx, h, t)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, t.BaseURL(), nil)
	if err != nil {
		h.Status = assets.HealthUnknown
		h.LastError = err.Error()
		h.ConsecutiveFailures = t.ConsecutiveFailures
		return h
	}

	client := &http.Client{
		Timeout: s.cfg.Timeout,
		Transport: &http.Transport{
			// verify_tls is honoured per device, matching the proxy: management UIs
			// commonly present self-signed certs.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !t.VerifyTLS}, //nolint:gosec // per-device policy
		},
		// A redirect is still a live device; don't chase it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// Some appliances reject HEAD outright at the transport level; retry once
		// with GET before calling the device down.
		if resp2, err2 := s.getFallback(ctx, client, t); err2 == nil {
			defer func() { _ = resp2.Body.Close() }()
			return s.online(h, start)
		}
		h.Status = assets.HealthOffline
		h.LastError = err.Error()
		h.ConsecutiveFailures = t.ConsecutiveFailures + 1
		return h
	}
	defer func() { _ = resp.Body.Close() }()
	return s.online(h, start)
}

// probeTCP reports whether something is listening on the device's port.
//
// A completed TCP handshake is the honest signal for a non-web device, and it is
// where this deliberately stops. Going further — reading an SSH banner, starting
// an RDP negotiation — would mean the platform authenticating to devices on a
// timer with nobody in the loop, and a failed liveness check must never be able
// to lock an account out. "Something is accepting connections on port 22" is
// exactly what an operator wants from a status dot; whether the credential works
// is what Connect is for.
func (s *Service) probeTCP(ctx context.Context, h assets.Health, t assets.ProbeTarget) assets.Health {
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
	if err != nil {
		h.Status = assets.HealthOffline
		h.LastError = err.Error()
		h.ConsecutiveFailures = t.ConsecutiveFailures + 1
		return h
	}
	_ = conn.Close()
	return s.online(h, start)
}

func (s *Service) getFallback(ctx context.Context, c *http.Client, t assets.ProbeTarget) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL(), nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (s *Service) online(h assets.Health, start time.Time) assets.Health {
	ms := int(time.Since(start).Milliseconds())
	h.Status = assets.HealthOnline
	h.LatencyMS = &ms
	h.ConsecutiveFailures = 0
	h.LastError = ""
	return h
}
