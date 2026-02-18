package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/potooio/potoo/internal/webhook"
)

// ServerConfig holds configuration for the webhook server.
type ServerConfig struct {
	// Addr is the address to listen on (e.g., ":8443").
	Addr string

	// TLSCertFile is the path to the TLS certificate file.
	// If empty and CertManager is set, certificates from CertManager are used.
	TLSCertFile string

	// TLSKeyFile is the path to the TLS key file.
	// If empty and CertManager is set, certificates from CertManager are used.
	TLSKeyFile string

	// CertManager manages TLS certificates (optional).
	CertManager *webhook.CertManager
}

// Server is the HTTPS server for the admission webhook.
type Server struct {
	config  ServerConfig
	handler *AdmissionHandler
	logger  *zap.Logger
	server  *http.Server
}

// NewServer creates a new webhook server.
func NewServer(config ServerConfig, handler *AdmissionHandler, logger *zap.Logger) *Server {
	return &Server{
		config:  config,
		handler: handler,
		logger:  logger.Named("server"),
	}
}

// Start starts the HTTPS server and blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.handler.Handle)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)

	s.server = &http.Server{
		Addr:         s.config.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS
	tlsConfig, err := s.getTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to configure TLS: %w", err)
	}
	s.server.TLSConfig = tlsConfig

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("Starting HTTPS server", zap.String("addr", s.config.Addr))

		var err error
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else if s.config.CertManager != nil {
			// Use in-memory certificates from CertManager
			err = s.server.ListenAndServeTLS("", "")
		} else {
			err = fmt.Errorf("no TLS configuration provided")
		}

		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down server")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// getTLSConfig creates the TLS configuration.
func (s *Server) getTLSConfig() (*tls.Config, error) {
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		// Use file-based certificates
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}, nil
	}

	if s.config.CertManager != nil {
		// Use dynamic certificate loading for hot-reload support
		return &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				_, certPEM, keyPEM := s.config.CertManager.GetCertificates()
				if len(certPEM) == 0 || len(keyPEM) == 0 {
					return nil, fmt.Errorf("CertManager has no certificates")
				}
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					return nil, fmt.Errorf("failed to load certificate: %w", err)
				}
				return &cert, nil
			},
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
		}, nil
	}

	return nil, fmt.Errorf("no TLS configuration provided")
}

// handleHealth handles the /healthz endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleReady handles the /readyz endpoint.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
