// Package config loads and validates runtime configuration following the
// Twelve-Factor App methodology: everything comes from the environment, and the
// process fails closed (returns an error) when a required or unsafe value is
// missing. No config file is read at runtime.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-validated application configuration. It is immutable after
// Load returns; downstream code receives it by value or read-only reference.
type Config struct {
	Env        string // "development" | "staging" | "production"
	HTTP       HTTPConfig
	Postgres   PostgresConfig
	Redis      RedisConfig
	Auth       AuthConfig
	Security   SecurityConfig
	Bootstrap  BootstrapConfig
	Federation FederationConfig
	Browser    BrowserConfig
	Desktop    DesktopConfig
	Health     HealthConfig
	Recording  RecordingConfig
	Session    SessionConfig
	Log        LogConfig
	Telemetry  TelemetryConfig
}

// HealthConfig controls the device liveness poller: how often the inventory is
// swept, how long a single probe may take, and how many run at once.
type HealthConfig struct {
	PollInterval time.Duration
	ProbeTimeout time.Duration
	Concurrency  int
}

// SessionConfig bounds how long a brokered session may live.
//
// Two limits, and they answer different questions. The one that ends a session
// in practice is neither of these — it is the per-device idle timeout
// (devices.idle_timeout_minutes, default 60), which is measured from the last
// keystroke or proxied request and so never cuts somebody off mid-task.
//
// These are the outer bounds around that.
type SessionConfig struct {
	// MaxWindow is the ceiling on a session with no approved window: the longest
	// it may run no matter how busy it is. It exists because an unbounded
	// privileged session is precisely what a privileged-access platform should
	// not hand out — a forgotten tab held open by a background poll would
	// otherwise live forever.
	MaxWindow time.Duration
	// ApprovalFallback is the window an approved request gets when neither the
	// requester nor the approver named one. Not a ceiling: an approver who says
	// thirty minutes gets thirty minutes, and activity does not extend it,
	// because a granted window that stretches while you type is not a window.
	ApprovalFallback time.Duration
	// EmergencyQuota is how many break-glass connects one person may take inside
	// EmergencyWindow. Zero disables the limit, which makes the approval gate
	// advisory: emergency access is reachable by anybody it applies to, so with
	// no counter on it nobody ever has to ask.
	EmergencyQuota  int
	EmergencyWindow time.Duration
}

// RecordingConfig controls where session recordings are stored and how long
// they are kept.
type RecordingConfig struct {
	// Dir is the root directory for recording artifacts.
	Dir string
	// MaxBytes caps the frames a single session may buffer before flush.
	MaxBytes int
	// RetentionDays seeds a tenant that has never set a retention policy. It is
	// NOT the live value: retention is an administrator's policy decision, so it
	// lives in org_settings and is edited in the console without a redeploy. This
	// is what a fresh organization inherits, and what the console offers as
	// "the value this deployment was installed with".
	//
	// Zero means keep recordings indefinitely, which is a choice a deployment may
	// legitimately make — and a different statement from having no policy at all.
	RetentionDays int
}

// BrowserConfig controls the browser-isolation access gateway. When enabled, web
// device sessions are rendered in a server-side headless Chromium and streamed to
// the user (instead of reverse-proxying the device HTML).
type BrowserConfig struct {
	Enabled    bool
	ChromePath string // path to the Chromium/Chrome binary ("" = autodetect)
	// SessionMemoryMB is the assumed cost of one isolated session, and
	// HostReserveMB the memory that must stay free after admitting one. There is
	// no max-session count on purpose: the platform admits from memory it
	// measures, so it uses whatever the machine actually has instead of a number
	// that is wrong on every host but the one it was tuned for.
	SessionMemoryMB int
	HostReserveMB   int
	// Screencast quality/geometry. These are the FPS levers: the headless
	// Chromium software-encodes one JPEG per frame, so fewer pixels (Width x
	// Height) and lower Quality mean cheaper frames and a higher achievable rate.
	// 0 leaves the gateway's own default (see browser.Config.defaults).
	Quality int
	Width   int
	Height  int
	// MaxFPS optionally caps how often a frame is pushed to the LIVE viewer
	// (the recorder still gets every frame). 0 means uncapped — send whatever
	// Chrome produces. It is a pacing/stability limit, not a way to exceed
	// Chrome's own capture rate.
	MaxFPS int
}

// DesktopConfig configures RDP/VNC brokering through guacd, the Apache Guacamole
// proxy daemon.
//
// Unlike browser isolation there is no binary to find: guacd is a service, so the
// only question is whether one is reachable. Disabled by default — a deployment
// with no desktops to broker should not be asked to run a sidecar it never uses.
type DesktopConfig struct {
	Enabled bool
	// Addr is guacd's host:port.
	Addr string
	// RecordingDir is where guacd writes session recordings. It has to be a path
	// BOTH guacd and the API can see: guacd writes the file, the API reads it back
	// on teardown and moves it into the blob store. Under compose that means a
	// shared volume, which is why this is configured rather than derived from the
	// recording directory.
	RecordingDir string
	// Width/Height/DPI are the desktop geometry requested of the device.
	Width, Height, DPI int
}

// FederationConfig configures external identity providers. Each provider is
// enabled only when its required fields plus ProvisionOrgID are present.
type FederationConfig struct {
	// ProvisionOrgID is the organization new federated users are provisioned into.
	ProvisionOrgID string

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	LDAPURL          string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPBaseDN       string
	LDAPUserFilter   string

	// SIEM is single sign-on from the SIEM: it authenticates the person and hands
	// GuardRail a short-lived signed assertion to trade for a session. It shares
	// ProvisionOrgID with the other providers above, because it answers the same
	// question — which tenant does a federated person belong to — and a second
	// setting for it would be a second thing to get wrong.
	SIEM SIEMSSOConfig
}

// SIEMSSOConfig configures the SIEM exchange-token flow. Every field is optional
// and every default reproduces the behaviour of a deployment that has never
// heard of the SIEM, which is what let this ship before the SIEM's half existed.
type SIEMSSOConfig struct {
	// JWKSURL is where the SIEM publishes its public keys. Setting it (with
	// ProvisionOrgID) is what enables SSO. HTTPS only.
	JWKSURL string
	// JWKSCABundle is the PEM certificate that must have signed the JWKS host's
	// TLS certificate, or that certificate itself when self-signed. A SIEM on a
	// private network almost always presents one, so on a fresh deployment the
	// fetch fails closed until this is pointed at it — which is correct. The
	// escape hatch is a pinned certificate, not a disabled check, and there is
	// deliberately no verify-off switch.
	JWKSCABundle string
	// SharedSecret enables the symmetric (HS256) path. Leave it empty. It exists
	// only so a SIEM that cannot yet sign asymmetrically is not blocked, and it
	// hands this process a key that can FORGE the SIEM's tokens rather than only
	// check them — which, next to just-in-time provisioning, means a leak of one
	// config value mints accounts rather than merely impersonating one.
	SharedSecret string

	Issuer   string // exact iss the token must carry
	Audience string // exact aud this consumer accepts; do not share it with another product

	JWKSCacheTTL    time.Duration
	ClockLeeway     time.Duration
	MaxTokenAge     time.Duration // longest validity a token may CLAIM
	NonceFloor      time.Duration // minimum replay-store retention
	NonceCeiling    time.Duration // maximum replay-store retention
	JITProvision    bool
	SyncOnLogin     bool
	TrustAMR        bool
	AllowlistBypass bool
	DefaultRole     string
	MaxRole         string
	RoleMapJSON     string
}

// Enabled reports whether the SIEM flow is fully configured. Key material alone
// is not enough: without a provisioning organization there is no answer to
// "which tenant is this person in", and the token must never be the thing that
// answers it.
func (f FederationConfig) SIEMSSOEnabled() bool {
	return f.ProvisionOrgID != "" && (f.SIEM.JWKSURL != "" || f.SIEM.SharedSecret != "")
}

// OIDCEnabled reports whether the OIDC provider is fully configured.
func (f FederationConfig) OIDCEnabled() bool {
	return f.ProvisionOrgID != "" && f.OIDCIssuer != "" && f.OIDCClientID != "" && f.OIDCRedirectURL != ""
}

// LDAPEnabled reports whether the LDAP provider is fully configured.
func (f FederationConfig) LDAPEnabled() bool {
	return f.ProvisionOrgID != "" && f.LDAPURL != "" && f.LDAPBaseDN != ""
}

type HTTPConfig struct {
	Addr        string // public API listen address, e.g. ":8080"
	MetricsAddr string // internal metrics/pprof listener, e.g. ":9090"
	WebDir      string // if set, the API also serves the web console from here
	TLSCert     string // path to a PEM cert; if set with TLSKey, the API serves HTTPS
	TLSKey      string // path to the matching PEM private key
	// TunnelDomain is the base domain for whole-host session delivery: a proxy
	// session is reachable at <session-id>.<TunnelDomain>, served at the root of
	// its own origin so a device UI needs no HTML rewriting. Empty disables it and
	// leaves every session on the /proxy/<sid>/ path transport.
	TunnelDomain string

	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	TrustedProxies  []string // CIDRs Gin trusts for X-Forwarded-For
}

type PostgresConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type AuthConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	JWTSigningKey   string // symmetric signing secret (>= 32 bytes)
	Issuer          string
}

type SecurityConfig struct {
	// MasterKey is the KEK used for envelope encryption of the credential vault.
	// It must be at least 32 bytes; the process refuses to start otherwise.
	MasterKey        string
	CORSAllowOrigins []string
	CookieDomain     string
	// TrustProxyHeaders enables honoring X-Forwarded-* — only true behind a
	// trusted edge proxy (Traefik).
	TrustProxyHeaders bool
}

// BootstrapConfig is the primary super admin seeded from the environment on first
// boot. Set (and change) these in .env before the first start; the admin is
// created automatically and idempotently. Leave empty to bootstrap manually with
// the `seed-admin` subcommand instead.
type BootstrapConfig struct {
	AdminEmail    string
	AdminPassword string
	AdminUsername string
	AdminOrg      string // organization slug (default: "default")
}

type LogConfig struct {
	Level  string // debug|info|warn|error
	Format string // json|console
}

type TelemetryConfig struct {
	OTLPEndpoint string // empty disables tracing export (no-op)
	ServiceName  string
}

// minSecretLen is the minimum acceptable length (bytes) for cryptographic
// secrets sourced from the environment.
const minSecretLen = 32

// Load reads configuration from the environment and validates it. It returns a
// joined error describing every problem found, so operators fix all at once.
func Load() (*Config, error) {
	c := &Config{
		Env: getEnv("GUARDRAIL_ENV", "development"),
		HTTP: HTTPConfig{
			Addr:            getEnv("GUARDRAIL_HTTP_ADDR", ":8080"),
			MetricsAddr:     getEnv("GUARDRAIL_METRICS_ADDR", ":9090"),
			WebDir:          getEnv("GUARDRAIL_WEB_DIR", ""),
			TunnelDomain:    strings.ToLower(strings.Trim(getEnv("GUARDRAIL_TUNNEL_DOMAIN", "tunnel.guardrail.lan"), ". ")),
			TLSCert:         getEnv("GUARDRAIL_TLS_CERT", ""),
			TLSKey:          getEnv("GUARDRAIL_TLS_KEY", ""),
			ReadTimeout:     getDuration("GUARDRAIL_HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    getDuration("GUARDRAIL_HTTP_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:     getDuration("GUARDRAIL_HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: getDuration("GUARDRAIL_HTTP_SHUTDOWN_TIMEOUT", 20*time.Second),
			TrustedProxies:  getCSV("GUARDRAIL_TRUSTED_PROXIES", nil),
		},
		Postgres: PostgresConfig{
			DSN:             getEnv("GUARDRAIL_POSTGRES_DSN", ""),
			MaxConns:        getInt32("GUARDRAIL_POSTGRES_MAX_CONNS", 10),
			MinConns:        getInt32("GUARDRAIL_POSTGRES_MIN_CONNS", 2),
			MaxConnLifetime: getDuration("GUARDRAIL_POSTGRES_CONN_LIFETIME", time.Hour),
		},
		Redis: RedisConfig{
			Addr:     getEnv("GUARDRAIL_REDIS_ADDR", "localhost:6379"),
			Password: getEnv("GUARDRAIL_REDIS_PASSWORD", ""),
			DB:       getInt("GUARDRAIL_REDIS_DB", 0),
		},
		Session: SessionConfig{
			MaxWindow:        getDuration("GUARDRAIL_MAX_SESSION_WINDOW", 12*time.Hour),
			ApprovalFallback: getDuration("GUARDRAIL_APPROVAL_WINDOW", time.Hour),
			EmergencyQuota:   getInt("GUARDRAIL_EMERGENCY_QUOTA", 2),
			EmergencyWindow:  getDuration("GUARDRAIL_EMERGENCY_QUOTA_WINDOW", 7*24*time.Hour),
		},
		Recording: RecordingConfig{
			Dir:           getEnv("GUARDRAIL_RECORDING_DIR", "/var/lib/guardrail/recordings"),
			MaxBytes:      getInt("GUARDRAIL_RECORDING_MAX_BYTES", 512<<20),
			RetentionDays: getInt("GUARDRAIL_RECORDING_RETENTION_DAYS", 90),
		},
		Health: HealthConfig{
			PollInterval: getDuration("GUARDRAIL_HEALTH_POLL_INTERVAL", 60*time.Second),
			ProbeTimeout: getDuration("GUARDRAIL_HEALTH_PROBE_TIMEOUT", 5*time.Second),
			Concurrency:  getInt("GUARDRAIL_HEALTH_CONCURRENCY", 16),
		},
		Auth: AuthConfig{
			AccessTokenTTL:  getDuration("GUARDRAIL_ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL: getDuration("GUARDRAIL_REFRESH_TOKEN_TTL", 720*time.Hour),
			JWTSigningKey:   getEnv("GUARDRAIL_JWT_SIGNING_KEY", ""),
			Issuer:          getEnv("GUARDRAIL_JWT_ISSUER", "guardrail"),
		},
		Security: SecurityConfig{
			MasterKey:         getEnv("GUARDRAIL_MASTER_KEY", ""),
			CORSAllowOrigins:  getCSV("GUARDRAIL_CORS_ALLOW_ORIGINS", []string{"http://localhost:5173"}),
			CookieDomain:      getEnv("GUARDRAIL_COOKIE_DOMAIN", ""),
			TrustProxyHeaders: getBool("GUARDRAIL_TRUST_PROXY_HEADERS", false),
		},
		Bootstrap: BootstrapConfig{
			AdminEmail:    getEnv("GUARDRAIL_ADMIN_EMAIL", ""),
			AdminPassword: getEnv("GUARDRAIL_ADMIN_PASSWORD", ""),
			AdminUsername: getEnv("GUARDRAIL_ADMIN_USERNAME", "admin"),
			AdminOrg:      getEnv("GUARDRAIL_ADMIN_ORG", "default"),
		},
		Federation: FederationConfig{
			ProvisionOrgID:   getEnv("GUARDRAIL_FEDERATION_ORG_ID", ""),
			OIDCIssuer:       getEnv("GUARDRAIL_OIDC_ISSUER", ""),
			OIDCClientID:     getEnv("GUARDRAIL_OIDC_CLIENT_ID", ""),
			OIDCClientSecret: getEnv("GUARDRAIL_OIDC_CLIENT_SECRET", ""),
			OIDCRedirectURL:  getEnv("GUARDRAIL_OIDC_REDIRECT_URL", ""),
			LDAPURL:          getEnv("GUARDRAIL_LDAP_URL", ""),
			LDAPBindDN:       getEnv("GUARDRAIL_LDAP_BIND_DN", ""),
			LDAPBindPassword: getEnv("GUARDRAIL_LDAP_BIND_PASSWORD", ""),
			LDAPBaseDN:       getEnv("GUARDRAIL_LDAP_BASE_DN", ""),
			LDAPUserFilter:   getEnv("GUARDRAIL_LDAP_USER_FILTER", ""),
			SIEM: SIEMSSOConfig{
				JWKSURL:      getEnv("GUARDRAIL_SIEM_JWKS_URL", ""),
				JWKSCABundle: getEnv("GUARDRAIL_SIEM_JWKS_CA_BUNDLE", ""),
				SharedSecret: getEnv("GUARDRAIL_SIEM_SSO_SECRET", ""),
				Issuer:       getEnv("GUARDRAIL_SIEM_SSO_ISSUER", "cybersentineldlp-siem"),
				Audience:     getEnv("GUARDRAIL_SIEM_SSO_AUDIENCE", "guardrail-pam"),
				JWKSCacheTTL: getDuration("GUARDRAIL_SIEM_JWKS_CACHE_TTL", 10*time.Minute),
				ClockLeeway:  getDuration("GUARDRAIL_SIEM_SSO_CLOCK_LEEWAY", time.Minute),
				MaxTokenAge:  getDuration("GUARDRAIL_SIEM_SSO_MAX_TOKEN_AGE", 10*time.Minute),
				NonceFloor:   getDuration("GUARDRAIL_SIEM_SSO_NONCE_FLOOR", 5*time.Minute),
				NonceCeiling: getDuration("GUARDRAIL_SIEM_SSO_NONCE_CEILING", time.Hour),
				JITProvision: getBool("GUARDRAIL_SIEM_SSO_JIT_PROVISION", true),
				SyncOnLogin:  getBool("GUARDRAIL_SIEM_SSO_SYNC_ON_LOGIN", true),
				// Both default OFF, and both defaults run the opposite way to the
				// obvious choice. See app/iam.SSOConfig.TrustAMR and
				// middleware.enforceSource: on a privileged-access broker, a second
				// factor somebody deliberately enrolled and an administrator's
				// address allowlist are each doing real work, and neither should be
				// switched off as a side effect of turning on single sign-on.
				TrustAMR:        getBool("GUARDRAIL_SIEM_SSO_TRUST_AMR", false),
				AllowlistBypass: getBool("GUARDRAIL_SIEM_SSO_ALLOWLIST_BYPASS", false),
				DefaultRole:     getEnv("GUARDRAIL_SIEM_SSO_DEFAULT_ROLE", "Read-only"),
				MaxRole:         getEnv("GUARDRAIL_SIEM_SSO_MAX_ROLE", ""),
				RoleMapJSON:     getEnv("GUARDRAIL_SIEM_SSO_ROLE_MAP", ""),
			},
		},
		Browser: BrowserConfig{
			Enabled:         getBool("GUARDRAIL_BROWSER_ISOLATION", false),
			ChromePath:      getEnv("GUARDRAIL_CHROME_PATH", ""),
			SessionMemoryMB: getInt("GUARDRAIL_ISOLATION_SESSION_MEMORY_MB", 400),
			HostReserveMB:   getInt("GUARDRAIL_ISOLATION_HOST_RESERVE_MB", 512),
			// 0 = let the gateway pick its default (1280x800 / q60, full sharpness).
			// Lower WIDTH/HEIGHT/QUALITY only if a host is encode- or bandwidth-bound;
			// measurement shows resolution does not change the frame rate here.
			Quality: getInt("GUARDRAIL_ISOLATION_QUALITY", 0),
			Width:   getInt("GUARDRAIL_ISOLATION_WIDTH", 0),
			Height:  getInt("GUARDRAIL_ISOLATION_HEIGHT", 0),
			MaxFPS:  getInt("GUARDRAIL_ISOLATION_MAX_FPS", 0),
		},
		Desktop: DesktopConfig{
			Enabled:      getBool("GUARDRAIL_DESKTOP_ENABLED", false),
			Addr:         getEnv("GUARDRAIL_GUACD_ADDR", "127.0.0.1:4822"),
			RecordingDir: getEnv("GUARDRAIL_GUACD_RECORDING_DIR", "/var/lib/guardrail/desktop-recordings"),
			Width:        getInt("GUARDRAIL_DESKTOP_WIDTH", 1280),
			Height:       getInt("GUARDRAIL_DESKTOP_HEIGHT", 800),
			DPI:          getInt("GUARDRAIL_DESKTOP_DPI", 96),
		},
		Log: LogConfig{
			Level:  getEnv("GUARDRAIL_LOG_LEVEL", "info"),
			Format: getEnv("GUARDRAIL_LOG_FORMAT", "json"),
		},
		Telemetry: TelemetryConfig{
			OTLPEndpoint: getEnv("GUARDRAIL_OTLP_ENDPOINT", ""),
			ServiceName:  getEnv("GUARDRAIL_SERVICE_NAME", "guardrail-api"),
		},
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// IsProduction reports whether the process runs in a production-like env, which
// tightens several defaults (e.g. secret enforcement).
func (c *Config) IsProduction() bool {
	return c.Env == "production" || c.Env == "staging"
}

func (c *Config) validate() error {
	var errs []error

	// These are converted to unsigned byte counts downstream, where a negative
	// would wrap to an enormous requirement and refuse every recorded session.
	// Reject at boot: an operator who typed a negative gets told, rather than a
	// platform that mysteriously stops recording.
	if c.Browser.SessionMemoryMB <= 0 {
		errs = append(errs, errors.New("GUARDRAIL_ISOLATION_SESSION_MEMORY_MB must be greater than 0"))
	}
	if c.Browser.HostReserveMB < 0 {
		errs = append(errs, errors.New("GUARDRAIL_ISOLATION_HOST_RESERVE_MB cannot be negative"))
	}

	if c.Postgres.DSN == "" {
		errs = append(errs, errors.New("GUARDRAIL_POSTGRES_DSN is required"))
	}
	if c.Auth.JWTSigningKey == "" {
		errs = append(errs, errors.New("GUARDRAIL_JWT_SIGNING_KEY is required"))
	} else if len(c.Auth.JWTSigningKey) < minSecretLen {
		errs = append(errs, fmt.Errorf("GUARDRAIL_JWT_SIGNING_KEY must be at least %d bytes", minSecretLen))
	}
	if c.Security.MasterKey == "" {
		errs = append(errs, errors.New("GUARDRAIL_MASTER_KEY is required"))
	} else if len(c.Security.MasterKey) < minSecretLen {
		errs = append(errs, fmt.Errorf("GUARDRAIL_MASTER_KEY must be at least %d bytes", minSecretLen))
	}
	if c.HTTP.Addr == "" {
		errs = append(errs, errors.New("GUARDRAIL_HTTP_ADDR is required"))
	}
	switch c.Log.Format {
	case "json", "console":
	default:
		errs = append(errs, fmt.Errorf("GUARDRAIL_LOG_FORMAT must be json|console, got %q", c.Log.Format))
	}

	// In production, refuse permissive CORS and demand proxy trust be explicit.
	if c.IsProduction() {
		for _, o := range c.Security.CORSAllowOrigins {
			if o == "*" {
				errs = append(errs, errors.New("wildcard CORS origin is not allowed in production"))
			}
		}
	}

	return errors.Join(errs...)
}

// ---- small env helpers (no external dependency) ----

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

// getInt32 reads an int setting that is stored as an int32, clamping instead of
// wrapping.
//
// The environment is untrusted input: `GUARDRAIL_POSTGRES_MAX_CONNS=3000000000`
// silently became a NEGATIVE pool size through a plain int32 conversion, and a
// negative pool is a database layer that refuses every connection at startup for
// no stated reason. Clamping keeps the failure legible — you asked for more than
// the type holds, you get the most it holds.
func getInt32(key string, def int32) int32 {
	n := getInt(key, int(def))
	switch {
	case n > math.MaxInt32:
		return math.MaxInt32
	case n < math.MinInt32:
		return math.MinInt32
	default:
		return int32(n)
	}
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return def
}

func getCSV(key string, def []string) []string {
	if v, ok := os.LookupEnv(key); ok {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return def
}
