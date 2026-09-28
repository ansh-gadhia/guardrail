package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/guardrail/guardrail/internal/infra/dnsrelay"
)

// runDNSGateway serves the encrypted ways into the bundled resolver — DNS over
// HTTPS and DNS over TLS — and encrypts the resolver's own lookups when its
// upstreams are DoH URLs.
//
// It runs beside dnsmasq on the host network (compose service "dns-gateway"),
// configured from the same .env the installer writes. Each protocol is on or
// off by itself, on a port of its own:
//
//	GUARDRAIL_DNS_DOH=yes|no      DNS over HTTPS (RFC 8484), /dns-query
//	GUARDRAIL_DNS_DOH_PORT        its port (default 443)
//	GUARDRAIL_DNS_DOT=yes|no      DNS over TLS (RFC 7858)
//	GUARDRAIL_DNS_DOT_PORT        its port (default 853)
//	GUARDRAIL_DNS_PLAIN=yes|no    whether dnsmasq answers plain DNS itself —
//	GUARDRAIL_DNS_PLAIN_PORT      and on which port, which is where the queries
//	                              here go on to
//	GUARDRAIL_HTTPS_PORT          the console's port (default 443)
//	GUARDRAIL_DNS_UPSTREAM[2]     an IP (plain DNS) or an https:// DoH URL
//
// DoH has two ways to be reached, decided by the ports:
//
//   - On the console's own port: Traefik already holds that port and its
//     certificate, so it routes /dns-query here, to a plain-HTTP listener on
//     the docker0 bridge address — reachable from Traefik's container as
//     host.docker.internal, and from nowhere on the network.
//   - On a port of its own: served here directly, over TLS, with the same
//     certificate the console uses. DoT is always served this way.
//
// Queries go on to dnsmasq on loopback, which holds the tunnel wildcard and the
// operator's records: on its plain DNS port when it serves plain DNS, on :5335
// when it does not and so listens on loopback only.
//
// With DoH and DoT both off and every upstream plain, there is nothing for it
// to do, and it says so and waits rather than exit: compose would restart it,
// and a restart loop reads as a fault.
func runDNSGateway(_ []string) error {
	logger := log.New(os.Stdout, "guardrail-dns-gateway: ", 0)
	cfg, err := gatewayConfigFromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 4)
	var lc net.ListenConfig
	certs := &certReloader{certFile: cfg.certFile, keyFile: cfg.keyFile}
	tlsConfig := func(what string) (*tls.Config, error) {
		if _, err := certs.get(nil); err != nil {
			return nil, fmt.Errorf("%s needs the console's certificate: %w", what, err)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.get}, nil
	}

	var srv *http.Server
	if cfg.doh {
		srv = &http.Server{
			Handler:           (&dnsrelay.Server{Backend: cfg.backend}).Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    16 << 10,
		}
		if cfg.shared {
			addr, err := interfaceAddr(cfg.sharedIface, cfg.sharedPort)
			if err != nil {
				return fmt.Errorf("DoH shares the console's port %s, which needs %s: %w", cfg.httpsPort, cfg.sharedIface, err)
			}
			ln, err := lc.Listen(ctx, "tcp", addr)
			if err != nil {
				return err
			}
			logger.Printf("DNS over HTTPS on the console's port %s (/dns-query, through Traefik) -> %s", cfg.httpsPort, cfg.backend)
			go func() { errc <- srv.Serve(ln) }()
		} else {
			conf, err := tlsConfig("DoH on port " + cfg.dohPort)
			if err != nil {
				return err
			}
			srv.TLSConfig = conf
			ln, err := lc.Listen(ctx, "tcp", ":"+cfg.dohPort)
			if err != nil {
				return fmt.Errorf("DoH cannot listen on port %s: %w", cfg.dohPort, err)
			}
			logger.Printf("DNS over HTTPS on port %s (/dns-query) -> %s", cfg.dohPort, cfg.backend)
			go func() { errc <- srv.ServeTLS(ln, "", "") }()
		}
	}

	if cfg.dot {
		conf, err := tlsConfig("DoT on port " + cfg.dotPort)
		if err != nil {
			return err
		}
		tl, err := lc.Listen(ctx, "tcp", ":"+cfg.dotPort)
		if err != nil {
			return fmt.Errorf("DoT cannot listen on port %s: %w", cfg.dotPort, err)
		}
		logger.Printf("DNS over TLS on port %s -> %s", cfg.dotPort, cfg.backend)
		go func() { errc <- (&dnsrelay.TLSServer{Backend: cfg.backend}).Serve(ctx, tls.NewListener(tl, conf)) }()
	}

	if len(cfg.upstreams) > 0 {
		fwd := &dnsrelay.Forwarder{Upstreams: cfg.upstreams, Client: &http.Client{Timeout: 5 * time.Second}}
		pc, err := lc.ListenPacket(ctx, "udp", cfg.forwardAddr)
		if err != nil {
			return fmt.Errorf("the resolver's DoH forwarder cannot listen on %s: %w", cfg.forwardAddr, err)
		}
		tl, err := lc.Listen(ctx, "tcp", cfg.forwardAddr)
		if err != nil {
			return fmt.Errorf("the resolver's DoH forwarder cannot listen on %s: %w", cfg.forwardAddr, err)
		}
		logger.Printf("the resolver's own lookups -> %s (over HTTPS)", strings.Join(cfg.upstreams, ", "))
		go func() { errc <- fwd.ServeUDP(ctx, pc) }()
		go func() { errc <- fwd.ServeTCP(ctx, tl) }()
	}

	if !cfg.doh && !cfg.dot && len(cfg.upstreams) == 0 {
		logger.Printf("nothing to serve: DoH and DoT are off and every upstream is plain DNS — idle")
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	if srv == nil {
		return nil
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shut)
}

type gatewayConfig struct {
	doh, dot          bool
	dohPort, dotPort  string
	httpsPort         string
	shared            bool
	sharedIface       string
	sharedPort        string
	backend           string
	certFile, keyFile string
	upstreams         []string
	forwardAddr       string
}

func gatewayConfigFromEnv() (gatewayConfig, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	on := func(k, def string) bool { return strings.EqualFold(env(k, def), "yes") }
	var bad []string
	port := func(k, def string) string {
		v := env(k, def)
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			bad = append(bad, fmt.Sprintf("%s=%q", k, v))
		}
		return v
	}
	c := gatewayConfig{
		doh:         on("GUARDRAIL_DNS_DOH", "no"),
		dot:         on("GUARDRAIL_DNS_DOT", "no"),
		dohPort:     port("GUARDRAIL_DNS_DOH_PORT", "443"),
		dotPort:     port("GUARDRAIL_DNS_DOT_PORT", "853"),
		httpsPort:   port("GUARDRAIL_HTTPS_PORT", "443"),
		sharedIface: env("GUARDRAIL_DOH_SHARED_INTERFACE", "docker0"),
		sharedPort:  port("GUARDRAIL_DOH_SHARED_PORT", "8053"),
		certFile:    env("GUARDRAIL_DOH_CERT", "/certs/cert.pem"),
		keyFile:     env("GUARDRAIL_DOH_KEY", "/certs/key.pem"),
		forwardAddr: env("GUARDRAIL_DOH_FORWARD_ADDR", "127.0.0.1:5053"),
	}
	dnsPort := "5335"
	if on("GUARDRAIL_DNS_PLAIN", "yes") {
		dnsPort = port("GUARDRAIL_DNS_PLAIN_PORT", "53")
	}
	if len(bad) > 0 {
		return c, fmt.Errorf("not a port number (1-65535): %s", strings.Join(bad, ", "))
	}
	c.shared = c.dohPort == c.httpsPort
	if c.doh && c.dot && !c.shared && c.dohPort == c.dotPort {
		return c, fmt.Errorf("DoH and DoT cannot share port %s", c.dohPort)
	}
	c.backend = env("GUARDRAIL_DNS_BACKEND", "127.0.0.1:"+dnsPort)
	for _, k := range []string{"GUARDRAIL_DNS_UPSTREAM", "GUARDRAIL_DNS_UPSTREAM2"} {
		if u := env(k, ""); strings.HasPrefix(u, "https://") {
			c.upstreams = append(c.upstreams, u)
		}
	}
	return c, nil
}

// interfaceAddr is ip:port for the named interface's first IPv4 address.
func interfaceAddr(name, port string) (string, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return net.JoinHostPort(n.IP.String(), port), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", name)
}

// certReloader serves the console's certificate and picks up a new one when
// the files change — an update regenerates it, and a gateway still presenting
// the old one would fail every client that checks the name.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	mod               time.Time
	checked           time.Time
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && time.Since(c.checked) < 30*time.Second {
		return c.cert, nil
	}
	c.checked = time.Now()
	st, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && !st.ModTime().After(c.mod) {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil // keep serving the last good one
		}
		return nil, err
	}
	c.cert, c.mod = &cert, st.ModTime()
	return c.cert, nil
}
