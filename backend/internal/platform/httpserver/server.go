// Package httpserver runs an http.Server with sane timeouts and graceful
// shutdown, satisfying the Twelve-Factor "disposability" factor.
package httpserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Server wraps http.Server with lifecycle helpers.
type Server struct {
	srv             *http.Server
	log             *zap.Logger
	name            string
	shutdownTimeout time.Duration
	tlsCert         string
	tlsKey          string
}

// Options configure a Server.
type Options struct {
	Addr            string
	Handler         http.Handler
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Name            string // for logs, e.g. "api" or "metrics"
	TLSCert         string // if both TLSCert and TLSKey are set, the server serves HTTPS
	TLSKey          string
}

// New constructs a Server.
func New(log *zap.Logger, opts Options) *Server {
	return &Server{
		log:             log,
		name:            opts.Name,
		shutdownTimeout: opts.ShutdownTimeout,
		tlsCert:         opts.TLSCert,
		tlsKey:          opts.TLSKey,
		srv: &http.Server{
			Addr:              opts.Addr,
			Handler:           opts.Handler,
			ReadTimeout:       opts.ReadTimeout,
			ReadHeaderTimeout: opts.ReadTimeout,
			WriteTimeout:      opts.WriteTimeout,
			IdleTimeout:       opts.IdleTimeout,
		},
	}
}

// Start blocks serving requests until the server is closed. It returns nil on a
// clean shutdown.
func (s *Server) Start() error {
	tls := s.tlsCert != "" && s.tlsKey != ""
	s.log.Info("http server starting",
		zap.String("server", s.name), zap.String("addr", s.srv.Addr), zap.Bool("tls", tls))
	var err error
	if tls {
		err = s.srv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	} else {
		err = s.srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully drains in-flight requests within the shutdown timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer cancel()
	s.log.Info("http server shutting down", zap.String("server", s.name))
	return s.srv.Shutdown(ctx)
}
