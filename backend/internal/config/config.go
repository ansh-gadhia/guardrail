// Package config loads and validates runtime configuration following the
// Twelve-Factor App methodology: everything comes from the environment, and the
// process fails closed (returns an error) when a required or unsafe value is
// missing. No config file is read at runtime.
package config

import (
	"errors"
	"fmt"
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

// RecordingConfig controls where session recordings are stored.
type RecordingConfig struct {
	// Dir is the root directory for recording artifacts.
	Dir string
	// MaxBytes caps the frames a single session may buffer before flush.
	MaxBytes int
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
			MaxConns:        int32(getInt("GUARDRAIL_POSTGRES_MAX_CONNS", 10)),
			MinConns:        int32(getInt("GUARDRAIL_POSTGRES_MIN_CONNS", 2)),
			MaxConnLifetime: getDuration("GUARDRAIL_POSTGRES_CONN_LIFETIME", time.Hour),
		},
		Redis: RedisConfig{
			Addr:     getEnv("GUARDRAIL_REDIS_ADDR", "localhost:6379"),
			Password: getEnv("GUARDRAIL_REDIS_PASSWORD", ""),
			DB:       getInt("GUARDRAIL_REDIS_DB", 0),
		},
		Recording: RecordingConfig{
			Dir:      getEnv("GUARDRAIL_RECORDING_DIR", "/var/lib/guardrail/recordings"),
			MaxBytes: getInt("GUARDRAIL_RECORDING_MAX_BYTES", 512<<20),
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
