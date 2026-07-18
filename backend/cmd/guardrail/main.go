// Command guardrail is the API service entrypoint and composition root. It wires
// concrete adapters (Postgres, Redis, metrics) into the delivery layer and
// manages process lifecycle with graceful shutdown. All configuration comes from
// the environment (Twelve-Factor).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/api"
	"github.com/guardrail/guardrail/internal/api/health"
	v1 "github.com/guardrail/guardrail/internal/api/v1"
	appaccess "github.com/guardrail/guardrail/internal/app/access"
	appanalytics "github.com/guardrail/guardrail/internal/app/analytics"
	appassets "github.com/guardrail/guardrail/internal/app/assets"
	apphealth "github.com/guardrail/guardrail/internal/app/health"
	appiam "github.com/guardrail/guardrail/internal/app/iam"
	appnotify "github.com/guardrail/guardrail/internal/app/notify"
	appvault "github.com/guardrail/guardrail/internal/app/vault"
	"github.com/guardrail/guardrail/internal/config"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/blob"
	"github.com/guardrail/guardrail/internal/infra/browser"
	infracache "github.com/guardrail/guardrail/internal/infra/cache"
	"github.com/guardrail/guardrail/internal/infra/federation"
	"github.com/guardrail/guardrail/internal/infra/guacgw"
	infranotify "github.com/guardrail/guardrail/internal/infra/notify"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/proxy"
	"github.com/guardrail/guardrail/internal/infra/security"
	"github.com/guardrail/guardrail/internal/infra/sshgw"
	"github.com/guardrail/guardrail/internal/infra/telnetgw"
	"github.com/guardrail/guardrail/internal/platform/cache"
	"github.com/guardrail/guardrail/internal/platform/database"
	"github.com/guardrail/guardrail/internal/platform/httpserver"
	"github.com/guardrail/guardrail/internal/platform/logger"
	"github.com/guardrail/guardrail/internal/platform/metrics"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Subcommands must be handled before flag parsing.
	if len(os.Args) > 1 && os.Args[1] == "seed-admin" {
		if err := runSeedAdmin(os.Args[2:]); err != nil {
			_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}

	// -healthcheck lets the distroless container (which has no shell or curl)
	// probe its own liveness endpoint for Docker/K8s health checks.
	hc := flag.Bool("healthcheck", false, "probe the local liveness endpoint and exit")
	flag.Parse()
	if *hc {
		os.Exit(healthcheck())
	}

	if err := run(); err != nil {
		// Logger may not exist yet; use stderr as a last resort.
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}
}

// startWorkers launches background loops: the notification dispatcher drains the
// outbox, the reaper expires overdue sessions, and the health poller probes
// device liveness. All stop when ctx is done.
func startWorkers(ctx context.Context, log *zap.Logger, notifySvc *appnotify.Service, broker *appaccess.Service, healthSvc *apphealth.Service) {
	if healthSvc != nil {
		go healthSvc.Run(ctx)
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if sent, failed := notifySvc.Dispatch(ctx, 50); sent+failed > 0 {
					log.Debug("notifications dispatched", zap.Int("sent", sent), zap.Int("failed", failed))
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := broker.ExpireOverdue(ctx); err == nil && n > 0 {
					log.Info("expired overdue sessions", zap.Int("count", n))
				}
				// Idle expiry is a separate sweep from the window: a session can be
				// well inside its grant and still have been abandoned twenty minutes
				// ago, which is the case that leaves a credential-injected door open
				// with nobody at it.
				if n, err := broker.ExpireIdle(ctx); err != nil {
					log.Warn("idle session sweep failed", zap.Error(err))
				} else if n > 0 {
					log.Info("ended idle sessions", zap.Int("count", n))
				}
			}
		}
	}()
}

// buildFederation constructs the optional OIDC and LDAP providers from config.
// A provider is returned as a nil interface (disabling it) unless fully
// configured, so the IAM service's enablement checks behave correctly.
func buildFederation(cfg config.FederationConfig, log *zap.Logger) (domiam.OIDCAuthenticator, domiam.PasswordAuthenticator, domiam.ID) {
	var oidc domiam.OIDCAuthenticator
	var ldap domiam.PasswordAuthenticator
	var orgID domiam.ID

	if cfg.ProvisionOrgID == "" {
		return nil, nil, orgID
	}
	parsed, err := uuid.Parse(cfg.ProvisionOrgID)
	if err != nil {
		log.Warn("federation disabled: invalid GUARDRAIL_FEDERATION_ORG_ID", zap.Error(err))
		return nil, nil, orgID
	}
	orgID = parsed

	if cfg.OIDCEnabled() {
		oidc = federation.NewOIDCProvider(federation.OIDCConfig{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret, RedirectURL: cfg.OIDCRedirectURL,
		})
		log.Info("OIDC federation enabled", zap.String("issuer", cfg.OIDCIssuer))
	}
	if cfg.LDAPEnabled() {
		ldap = federation.NewLDAPAuthenticator(federation.LDAPConfig{
			URL: cfg.LDAPURL, BindDN: cfg.LDAPBindDN, BindPassword: cfg.LDAPBindPassword,
			BaseDN: cfg.LDAPBaseDN, UserFilter: cfg.LDAPUserFilter,
		})
		log.Info("LDAP federation enabled", zap.String("url", cfg.LDAPURL))
	}
	return oidc, ldap, orgID
}

// healthcheck performs an in-process HTTP GET against the liveness probe. Returns
// a process exit code (0 healthy, 1 otherwise).
func healthcheck() int {
	addr := os.Getenv("GUARDRAIL_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + addr + "/healthz")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log, err := logger.New(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	log.Info("starting guardrail", zap.String("version", version), zap.String("env", cfg.Env))

	// Root context cancelled on SIGINT/SIGTERM for coordinated shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Backing services (attached resources) ---
	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	db, err := database.New(startCtx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("connected to postgres")

	rdb, err := cache.New(startCtx, cfg.Redis)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()
	log.Info("connected to redis")

	// --- Cross-cutting platform ---
	reg := metrics.New()
	healthH := health.New(version).
		Register("postgres", db).
		Register("redis", rdb)

	// --- IAM module (M2): repositories, security adapters, service, handler ---
	pg := postgres.New(db.Pool)
	hasher := security.NewArgon2Hasher(security.DefaultArgon2Params())
	issuer := security.NewJWTIssuer(cfg.Auth.JWTSigningKey, cfg.Auth.Issuer, cfg.Auth.AccessTokenTTL)

	// Envelope encryptor is shared by the vault and by MFA (to protect TOTP
	// secrets under the same KEK), so it is constructed before the IAM service.
	keyProvider, err := security.NewEnvKeyProvider(cfg.Security.MasterKey)
	if err != nil {
		return err
	}
	encryptor := security.NewEnvelopeEncryptor(keyProvider)

	// Federation providers (M3) are optional and activate only when configured.
	oidcProvider, ldapProvider, fedOrgID := buildFederation(cfg.Federation, log)

	iamCfg := appiam.DefaultConfig()
	iamCfg.RefreshTTL = cfg.Auth.RefreshTokenTTL
	iamSvc := appiam.NewService(appiam.Deps{
		Users:    postgres.NewUserRepo(pg),
		Orgs:     postgres.NewOrgRepo(pg),
		Roles:    postgres.NewRoleRepo(pg),
		Sessions: postgres.NewAuthSessionRepo(pg),
		Hasher:   hasher,
		Tokens:   issuer,
		Refresh:  security.NewRefreshGenerator(),
		Audit:    postgres.NewAuditRepo(pg),
		Throttle: infracache.NewThrottle(rdb.Client, iamCfg.MaxLoginFailures*2, iamCfg.LockoutDuration),
		Config:   iamCfg,
		// --- MFA (M3) ---
		MFA:       postgres.NewMFARepo(pg),
		TOTP:      security.NewTOTP(),
		Cipher:    encryptor,
		MFAChal:   security.NewMFAChallenger(cfg.Auth.JWTSigningKey, 5*time.Minute),
		MFAIssuer: "GuardRail",
		// --- Federation (M3) ---
		OIDC:            oidcProvider,
		LDAP:            ldapProvider,
		FederationOrgID: fedOrgID,
	})
	// Primary super admin from the environment (GUARDRAIL_ADMIN_*). Idempotent:
	// created once on first boot, a no-op thereafter. Fails closed on a weak
	// password so a misconfigured primary credential is caught immediately.
	if created, err := iamSvc.EnsureBootstrapAdmin(startCtx, appiam.BootstrapAdminInput{
		Email:    cfg.Bootstrap.AdminEmail,
		Password: cfg.Bootstrap.AdminPassword,
		Username: cfg.Bootstrap.AdminUsername,
		OrgSlug:  cfg.Bootstrap.AdminOrg,
	}); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	} else if created {
		log.Info("bootstrapped primary super admin from environment", zap.String("email", cfg.Bootstrap.AdminEmail))
	}

	iamHandler := v1.NewHandler(iamSvc, v1.CookieConfig{
		Domain:     cfg.Security.CookieDomain,
		Secure:     cfg.IsProduction(),
		RefreshTTL: cfg.Auth.RefreshTokenTTL,
	}, security.NewCookieSigner(cfg.Auth.JWTSigningKey))

	// --- Assets + Vault modules (M4) ---
	auditRec := postgres.NewAuditRepo(pg)
	assetsSvc := appassets.NewService(postgres.NewDeviceRepo(pg), postgres.NewAssetGroupRepo(pg), auditRec)
	vaultSvc := appvault.NewService(postgres.NewCredentialRepo(pg), encryptor, auditRec)
	assetsHandler := v1.NewAssetsHandler(assetsSvc, vaultSvc)

	// --- Notifications (M6) ---
	notifySvc := appnotify.NewService(
		postgres.NewChannelRepo(pg),
		postgres.NewOutboxRepo(pg),
		infranotify.NewRouter(nil, nil),
		nil,
		auditRec,
	)
	notifyHandler := v1.NewNotifyHandler(notifySvc)

	// --- Access broker + Proxy gateway + recording (M5/M6) ---
	deviceRepo := postgres.NewDeviceRepo(pg)
	sessionRepo := postgres.NewAccessSessionRepo(pg)
	eventRepo := postgres.NewSessionEventRepo(pg)
	recordingRepo := postgres.NewRecordingRepo(pg)
	liveRegistry := infracache.NewLiveRegistry(rdb.Client)
	deviceLookup := appaccess.NewDeviceLookup(deviceRepo)
	credResolver := appaccess.NewCredentialResolver(vaultSvc)

	// Recording artifacts land on disk. A nil store disables capture rather than
	// failing the whole server: sessions still broker, they just aren't recorded.
	var blobStore domaccess.BlobStore
	if fsStore, berr := blob.NewFS(cfg.Recording.Dir); berr != nil {
		log.Warn("recording storage unavailable; sessions will not be captured", zap.Error(berr))
	} else {
		blobStore = fsStore
		log.Info("recording storage ready", zap.String("dir", cfg.Recording.Dir))
	}

	// Delivery is chosen per device, not per deployment. The reverse proxy serves
	// ordinary sessions; devices set to be recorded go through browser isolation,
	// which is the only mode that can produce frames to record. Both satisfy the
	// broker's Gateway contract and the delivery SessionServer, so both can be
	// live at once and the mux routes each request to whichever holds the session.
	// Both gateways report operator activity to the same tracker, so the idle
	// reaper sees a busy session as busy whichever way it is being delivered.
	activity := appaccess.NewActivityTracker(sessionRepo, nil, 30*time.Second)

	proxyGateway := proxy.NewHTTPGateway(deviceLookup, eventRepo, activity, cfg.Telemetry.ServiceName)
	sessionServers := []v1.SessionServer{proxyGateway}
	var isolatedGateways []domaccess.Gateway

	// Resolve the browser before advertising isolation. Registering it on the
	// config flag alone meant a host with no Chromium still logged "isolation
	// available" and still told the console that session recording worked, so a
	// device could be marked recorded on a promise this host could not keep — and
	// the only symptom was HTTP 500 on Connect.
	chromePath, chromeErr := browser.ResolveChromePath(cfg.Browser.ChromePath)
	if cfg.Browser.Enabled && chromeErr != nil {
		log.Warn("browser isolation is switched on but unavailable: no usable Chromium. "+
			"Recorded devices will fall back to the reverse proxy and WILL NOT be recorded; "+
			"the console will report session recording as unavailable",
			zap.Error(chromeErr))
	}
	if cfg.Browser.Enabled && chromeErr == nil {
		bgw := browser.NewGateway(
			browser.Config{
				// The resolved path, not the configured one: with autodetect, config
				// is empty and chromedp would fall back to exec'ing "google-chrome".
				ChromePath:            chromePath,
				Node:                  cfg.Telemetry.ServiceName,
				SessionMemoryEstimate: uint64(cfg.Browser.SessionMemoryMB) << 20,
				HostReserve:           uint64(cfg.Browser.HostReserveMB) << 20,
				// Screencast tuning. Zero values fall through to Config.defaults;
				// previously these were never passed at all, so the env vars had no
				// effect and the recorder cap silently ignored GUARDRAIL_RECORDING_MAX_BYTES.
				Quality:           int64(cfg.Browser.Quality),
				Width:             int64(cfg.Browser.Width),
				Height:            int64(cfg.Browser.Height),
				MaxFPS:            cfg.Browser.MaxFPS,
				MaxRecordingBytes: cfg.Recording.MaxBytes,
			},
			browser.Deps{
				Devices:    deviceLookup,
				Events:     eventRepo,
				Recordings: recordingRepo,
				Blobs:      blobStore,
				Activity:   activity,
				Log:        log,
			},
		)
		isolatedGateways = append(isolatedGateways, bgw)
		// Isolated first: it is the more specific owner, and the proxy declines
		// ids it does not hold, so order only affects how many map lookups a
		// request costs.
		sessionServers = append([]v1.SessionServer{bgw}, sessionServers...)
		log.Info("browser isolation available; devices set to isolated delivery, and every recorded web device, will use it",
			zap.String("chrome_path", chromePath))
	} else if !cfg.Browser.Enabled {
		log.Info("browser isolation disabled; web sessions are all reverse-proxied, " +
			"devices set to isolated delivery fall back to the proxy, and recorded web devices are refused")
	}

	// SSH. Unlike browser isolation there is nothing to switch off: it needs no
	// Chromium and no extra process, only a TCP connection the API already makes
	// to reach devices. A recorded SSH session is captured as text by the gateway
	// itself, so it is never "available but unrecordable" the way isolation can be.
	sshGateway := sshgw.NewGateway(sshgw.Config{}, sshgw.Deps{
		Devices:    deviceLookup,
		Events:     eventRepo,
		Recordings: recordingRepo,
		Blobs:      blobStore,
		Activity:   activity,
		// Trust-on-first-use. Without a policy the gateway refuses every
		// connection, which is the correct default but useless in practice, so
		// one is always wired here.
		HostKeys: sshgw.TOFU{Store: postgres.NewHostKeyRepo(pg)},
		Log:      log,
	})
	sessionServers = append(sessionServers, sshGateway)

	// Telnet, native for the same reasons as SSH. It was previously routed
	// through guacd, which does speak telnet — but that means a remote desktop
	// daemon rasterises a router console into a canvas and streams it back as
	// drawing instructions. It works, and it feels like screen sharing, because
	// that is what it is. Carried natively a Cisco console is what it always was:
	// a byte stream, delivered as text, recorded as a transcript an investigator
	// can grep.
	telnetGateway := telnetgw.NewGateway(telnetgw.Config{}, telnetgw.Deps{
		Devices:    deviceLookup,
		Events:     eventRepo,
		Recordings: recordingRepo,
		Blobs:      blobStore,
		Activity:   activity,
		Log:        log,
	})
	// The two text protocols, which between them need no sidecar at all.
	terminalGateways := []domaccess.Gateway{sshGateway, telnetGateway}
	sessionServers = append(sessionServers, telnetGateway)

	// RDP and VNC, brokered through guacd. Off unless a sidecar is configured:
	// unlike SSH this needs a service running, and a deployment with no desktops
	// should not be asked to run one it never uses. When it is off, connecting to
	// an RDP device is refused with "no gateway for this device protocol" rather
	// than failing somewhere less honest.
	desktopGateways := []domaccess.Gateway{}
	if cfg.Desktop.Enabled {
		guacCfg := guacgw.Config{
			Addr:         cfg.Desktop.Addr,
			RecordingDir: cfg.Desktop.RecordingDir,
			Width:        cfg.Desktop.Width,
			Height:       cfg.Desktop.Height,
			DPI:          cfg.Desktop.DPI,
		}
		guacDeps := guacgw.Deps{
			Devices:    deviceLookup,
			Recordings: recordingRepo,
			Blobs:      blobStore,
			Activity:   activity,
			Events:     eventRepo,
			Log:        log,
		}
		// One gateway per protocol: the broker routes by protocol and a gateway
		// reports exactly one. guacd makes them otherwise identical.
		//
		// Telnet is deliberately not in this list any more. Two gateways claiming
		// one protocol is not a fallback, it is an ambiguity — the broker picks
		// whichever it sees first, so the delivery mode of a device would depend
		// on slice order rather than on anything a reader could reason about.
		for _, proto := range []domaccess.Protocol{
			domaccess.ProtocolRDP, domaccess.ProtocolVNC,
		} {
			gw := guacgw.NewGateway(proto, guacCfg, guacDeps)
			desktopGateways = append(desktopGateways, gw)
			sessionServers = append(sessionServers, gw)
		}
		log.Info("desktop brokering available; RDP and VNC devices will be served through guacd",
			zap.String("guacd", cfg.Desktop.Addr),
			zap.String("recording_dir", cfg.Desktop.RecordingDir))
	} else {
		log.Info("desktop brokering disabled; RDP and VNC devices cannot be connected to " +
			"(set GUARDRAIL_DESKTOP_ENABLED and run a guacd sidecar). Telnet is unaffected: " +
			"it is served natively and needs no sidecar")
	}

	sessionServer := v1.SessionMux(sessionServers)

	brokerSvc := appaccess.NewService(appaccess.Deps{
		Sessions:         sessionRepo,
		Authorizer:       postgres.NewAuthorizerRepo(pg),
		Gateways:         append(append([]domaccess.Gateway{proxyGateway}, terminalGateways...), desktopGateways...),
		IsolatedGateways: isolatedGateways,
		Activity:         activity,
		Registry:         liveRegistry,
		Events:           eventRepo,
		Recordings:       recordingRepo,
		Blobs:            blobStore,
		Devices:          deviceLookup,
		Creds:            credResolver,
		Audit:            auditRec,
		Notifier:         notifySvc,
		Node:             cfg.Telemetry.ServiceName,
		Config:           appaccess.DefaultConfig(),
		Log:              log,
	})
	accessHandler := v1.NewAccessHandler(brokerSvc, sessionServer, cfg.IsProduction())

	// --- Analytics: dashboard, search, audit log, reports (M8) ---
	analyticsSvc := appanalytics.NewService(postgres.NewAnalyticsRepo(pg))
	analyticsHandler := v1.NewAnalyticsHandler(analyticsSvc)

	// --- Device liveness (M-health) ---
	healthSvc := apphealth.NewService(postgres.NewHealthRepo(pg), log, apphealth.Config{
		Interval:    cfg.Health.PollInterval,
		Timeout:     cfg.Health.ProbeTimeout,
		Concurrency: cfg.Health.Concurrency,
	})

	// Background workers: notification dispatcher, overdue-session reaper, health poller.
	startWorkers(ctx, log, notifySvc, brokerSvc, healthSvc)

	// Cross-node terminate: when any node terminates a session it publishes a
	// signal; every gateway node tears down its local state on receipt so the
	// session stops serving immediately, not just on the node that handled the
	// terminate call. The signal carries only the session id, so — as in the
	// broker's own teardown — every gateway is asked; each ignores an id it does
	// not hold. Missing one here would leave a live Chromium serving a session
	// that the rest of the cluster considers ended.
	allGateways := append([]domaccess.Gateway{proxyGateway}, isolatedGateways...)
	allGateways = append(allGateways, terminalGateways...)
	go func() {
		if err := liveRegistry.SubscribeTerminate(ctx, func(sid uuid.UUID) {
			for _, gw := range allGateways {
				_ = gw.End(context.Background(), sid)
			}
		}); err != nil && ctx.Err() == nil {
			log.Warn("terminate subscriber stopped", zap.Error(err))
		}
	}()

	// --- Delivery layer ---
	router, err := api.New(api.Deps{
		Config:        cfg,
		Logger:        log,
		Metrics:       reg,
		Health:        healthH,
		IAM:           iamHandler,
		Assets:        assetsHandler,
		Access:        accessHandler,
		Notify:        notifyHandler,
		Analytics:     analyticsHandler,
		Authenticator: issuer,
		WebDir:        cfg.HTTP.WebDir,
		Version:       version,
	})
	if err != nil {
		return err
	}

	apiSrv := httpserver.New(log, httpserver.Options{
		Addr:            cfg.HTTP.Addr,
		Handler:         router,
		ReadTimeout:     cfg.HTTP.ReadTimeout,
		WriteTimeout:    cfg.HTTP.WriteTimeout,
		IdleTimeout:     cfg.HTTP.IdleTimeout,
		ShutdownTimeout: cfg.HTTP.ShutdownTimeout,
		Name:            "api",
		TLSCert:         cfg.HTTP.TLSCert,
		TLSKey:          cfg.HTTP.TLSKey,
	})

	// Metrics served on a separate, internal-only listener (not exposed at edge).
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg.Prom, promhttp.HandlerOpts{}))
	metricsSrv := httpserver.New(log, httpserver.Options{
		Addr:            cfg.HTTP.MetricsAddr,
		Handler:         metricsMux,
		ReadTimeout:     cfg.HTTP.ReadTimeout,
		WriteTimeout:    cfg.HTTP.WriteTimeout,
		IdleTimeout:     cfg.HTTP.IdleTimeout,
		ShutdownTimeout: cfg.HTTP.ShutdownTimeout,
		Name:            "metrics",
	})

	// Run both servers; the first to error (or a signal) triggers shutdown.
	errCh := make(chan error, 2)
	go func() { errCh <- apiSrv.Start() }()
	go func() { errCh <- metricsSrv.Start() }()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			log.Error("server error, initiating shutdown", zap.Error(err))
		}
	}

	shutdownCtx := context.Background()
	if e := apiSrv.Shutdown(shutdownCtx); e != nil {
		log.Error("api shutdown error", zap.Error(e))
		err = errors.Join(err, e)
	}
	if e := metricsSrv.Shutdown(shutdownCtx); e != nil {
		log.Error("metrics shutdown error", zap.Error(e))
		err = errors.Join(err, e)
	}
	log.Info("shutdown complete")
	return err
}
