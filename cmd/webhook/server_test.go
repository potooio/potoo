package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/webhook"
)

// ---------------------------------------------------------------------------
// NewServer
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	logger := zap.NewNop()
	querier := &mockQuerier{}
	handler := NewAdmissionHandler(querier, logger)

	cfg := ServerConfig{
		Addr:        ":9443",
		TLSCertFile: "/tmp/cert.pem",
		TLSKeyFile:  "/tmp/key.pem",
	}

	srv := NewServer(cfg, handler, logger)

	require.NotNil(t, srv)
	assert.Equal(t, ":9443", srv.config.Addr)
	assert.Equal(t, "/tmp/cert.pem", srv.config.TLSCertFile)
	assert.Equal(t, "/tmp/key.pem", srv.config.TLSKeyFile)
	assert.Equal(t, handler, srv.handler)
	assert.NotNil(t, srv.logger)
}

func TestNewServer_WithCertManager(t *testing.T) {
	logger := zap.NewNop()
	querier := &mockQuerier{}
	handler := NewAdmissionHandler(querier, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.DefaultCertManagerConfig("test-ns")
	cm := webhook.NewCertManager(client, certCfg, logger)

	cfg := ServerConfig{
		Addr:        ":8443",
		CertManager: cm,
	}

	srv := NewServer(cfg, handler, logger)

	require.NotNil(t, srv)
	assert.Equal(t, cm, srv.config.CertManager)
	assert.Empty(t, srv.config.TLSCertFile)
	assert.Empty(t, srv.config.TLSKeyFile)
}

// ---------------------------------------------------------------------------
// handleHealth
// ---------------------------------------------------------------------------

func TestHandleHealth(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)
	srv := NewServer(ServerConfig{}, handler, logger)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestHandleHealth_POST(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)
	srv := NewServer(ServerConfig{}, handler, logger)

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	// handleHealth does not check the method; it always returns ok.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

// ---------------------------------------------------------------------------
// handleReady
// ---------------------------------------------------------------------------

func TestHandleReady(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)
	srv := NewServer(ServerConfig{}, handler, logger)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	srv.handleReady(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestHandleReady_POST(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)
	srv := NewServer(ServerConfig{}, handler, logger)

	req := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	w := httptest.NewRecorder()

	srv.handleReady(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

// ---------------------------------------------------------------------------
// getTLSConfig -- file-based certs
// ---------------------------------------------------------------------------

func TestGetTLSConfig_FileBasedCerts(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	srv := NewServer(ServerConfig{
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
	}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	// File-based mode should not set GetCertificate callback.
	assert.Nil(t, tlsCfg.GetCertificate)
}

// ---------------------------------------------------------------------------
// getTLSConfig -- CertManager certs
// ---------------------------------------------------------------------------

func TestGetTLSConfig_CertManagerCerts(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.CertManagerConfig{
		Mode:              webhook.CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := webhook.NewCertManager(client, certCfg, logger)

	// Generate real certificates so GetCertificates returns non-empty data.
	err := cm.EnsureCertificates(context.Background())
	require.NoError(t, err)

	srv := NewServer(ServerConfig{
		CertManager: cm,
	}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.NotNil(t, tlsCfg.GetCertificate, "CertManager path should set GetCertificate callback")
	// PreferServerCipherSuites is deprecated since Go 1.18 and ignored.
	// TLS 1.3 cipher suites are not configurable; Go handles them.
	assert.Contains(t, tlsCfg.CurvePreferences, tls.X25519)
	assert.Contains(t, tlsCfg.CurvePreferences, tls.CurveP256)
}

func TestGetTLSConfig_CertManagerCerts_GetCertificateCallback(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.CertManagerConfig{
		Mode:              webhook.CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := webhook.NewCertManager(client, certCfg, logger)

	// Generate certificates so the callback can return them.
	err := cm.EnsureCertificates(context.Background())
	require.NoError(t, err)

	srv := NewServer(ServerConfig{
		CertManager: cm,
	}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	require.NoError(t, err)

	// Invoke the GetCertificate callback -- it should succeed.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
}

func TestGetTLSConfig_CertManagerCerts_EmptyCerts(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.DefaultCertManagerConfig("test-ns")
	cm := webhook.NewCertManager(client, certCfg, logger)
	// Do NOT call EnsureCertificates -- certs remain empty.

	srv := NewServer(ServerConfig{
		CertManager: cm,
	}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// Callback should fail because CertManager has no certificates.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "CertManager has no certificates")
}

// ---------------------------------------------------------------------------
// getTLSConfig -- no certs at all
// ---------------------------------------------------------------------------

func TestGetTLSConfig_NoCerts(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	srv := NewServer(ServerConfig{}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	assert.Error(t, err)
	assert.Nil(t, tlsCfg)
	assert.Contains(t, err.Error(), "no TLS configuration provided")
}

// ---------------------------------------------------------------------------
// getTLSConfig -- file-based takes priority over CertManager
// ---------------------------------------------------------------------------

func TestGetTLSConfig_FileBasedTakesPriority(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.DefaultCertManagerConfig("test-ns")
	cm := webhook.NewCertManager(client, certCfg, logger)

	srv := NewServer(ServerConfig{
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
		CertManager: cm,
	}, handler, logger)

	tlsCfg, err := srv.getTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// File-based mode should be used, so GetCertificate should NOT be set.
	assert.Nil(t, tlsCfg.GetCertificate, "file-based config should take priority over CertManager")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
}

// ---------------------------------------------------------------------------
// Start -- basic lifecycle (context cancellation)
// ---------------------------------------------------------------------------

func TestStart_NoCerts_ReturnsError(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	srv := NewServer(ServerConfig{
		Addr: ":0",
	}, handler, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to configure TLS")
}

func TestStart_FileBasedCerts(t *testing.T) {
	certFile, keyFile := generateTempCertFiles(t, "localhost")

	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	srv := NewServer(ServerConfig{
		Addr:        ":0", // kernel-assigned port
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, handler, logger)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Give the server a moment to start.
	time.Sleep(200 * time.Millisecond)

	// Cancel context to trigger graceful shutdown.
	cancel()

	select {
	case err := <-errCh:
		// Shutdown error is acceptable (nil or server closed).
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop within timeout")
	}
}

func TestStart_CertManagerCerts(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	client := fake.NewSimpleClientset()
	certCfg := webhook.CertManagerConfig{
		Mode:              webhook.CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "localhost",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := webhook.NewCertManager(client, certCfg, logger)
	err := cm.EnsureCertificates(context.Background())
	require.NoError(t, err)

	srv := NewServer(ServerConfig{
		Addr:        ":0",
		CertManager: cm,
	}, handler, logger)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop within timeout")
	}
}

// ---------------------------------------------------------------------------
// Start -- integration: verify endpoints are wired correctly
// ---------------------------------------------------------------------------

func TestStart_EndpointsWired(t *testing.T) {
	certFile, keyFile := generateTempCertFiles(t, "localhost")

	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := NewServer(ServerConfig{
		Addr:        addr,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, handler, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for the server to be ready.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}

	var lastErr error
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := httpClient.Get(fmt.Sprintf("https://%s/healthz", addr))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			lastErr = nil
			break
		}
	}
	require.NoError(t, lastErr, "server should become ready")

	// Test /healthz
	resp, err := httpClient.Get(fmt.Sprintf("https://%s/healthz", addr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Test /readyz
	resp, err = httpClient.Get(fmt.Sprintf("https://%s/readyz", addr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop within timeout")
	}
}

// ---------------------------------------------------------------------------
// NewConstraintClient
// ---------------------------------------------------------------------------

func TestNewConstraintClient(t *testing.T) {
	logger := zap.NewNop()
	client := NewConstraintClient("http://localhost:8080", logger)

	require.NotNil(t, client)
	assert.Equal(t, "http://localhost:8080", client.baseURL)
	assert.NotNil(t, client.httpClient)
	assert.NotNil(t, client.logger)

	// Verify the HTTP client has a timeout.
	assert.Equal(t, 5*time.Second, client.httpClient.Timeout)
}

func TestNewConstraintClient_CustomURL(t *testing.T) {
	logger := zap.NewNop()
	client := NewConstraintClient("http://controller.potoo.svc:9090", logger)

	require.NotNil(t, client)
	assert.Equal(t, "http://controller.potoo.svc:9090", client.baseURL)
}

func TestNewConstraintClient_TransportSettings(t *testing.T) {
	logger := zap.NewNop()
	client := NewConstraintClient("http://localhost:8080", logger)

	require.NotNil(t, client.httpClient.Transport)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, 10, transport.MaxIdleConns)
	assert.Equal(t, 10, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	assert.False(t, transport.DisableCompression)
}

// ---------------------------------------------------------------------------
// ConstraintClient.Query -- success
// ---------------------------------------------------------------------------

func TestConstraintClient_Query(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/constraints", r.URL.Path)
		assert.Equal(t, "test-ns", r.URL.Query().Get("namespace"))
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"constraints": []types.Constraint{
				{Name: "test-constraint", Severity: types.SeverityWarning, Summary: "test summary"},
			},
		})
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.NoError(t, err)
	require.Len(t, constraints, 1)
	assert.Equal(t, "test-constraint", constraints[0].Name)
	assert.Equal(t, types.SeverityWarning, constraints[0].Severity)
	assert.Equal(t, "test summary", constraints[0].Summary)
}

func TestConstraintClient_Query_EmptyResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"constraints": []types.Constraint{},
		})
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "default", nil)
	require.NoError(t, err)
	assert.Empty(t, constraints)
}

func TestConstraintClient_Query_MultipleConstraints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"constraints": []types.Constraint{
				{Name: "constraint-a", Severity: types.SeverityWarning},
				{Name: "constraint-b", Severity: types.SeverityCritical},
				{Name: "constraint-c", Severity: types.SeverityInfo},
			},
		})
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.NoError(t, err)
	assert.Len(t, constraints, 3)
}

// ---------------------------------------------------------------------------
// ConstraintClient.Query -- namespace URL encoding
// ---------------------------------------------------------------------------

func TestConstraintClient_Query_NamespaceEncoding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The namespace "ns with space" should be URL-encoded in the query param.
		assert.Equal(t, "ns with space", r.URL.Query().Get("namespace"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"constraints": []types.Constraint{},
		})
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	_, err := client.Query(context.Background(), "ns with space", nil)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ConstraintClient.Query -- error cases
// ---------------------------------------------------------------------------

func TestConstraintClient_Query_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
	assert.Contains(t, err.Error(), "controller returned status 500")
	assert.Contains(t, err.Error(), "internal error")
}

func TestConstraintClient_Query_Non200_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
	assert.Contains(t, err.Error(), "controller returned status 404")
}

func TestConstraintClient_Query_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{invalid json"))
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestConstraintClient_Query_ConnectionRefused(t *testing.T) {
	// Point at a server that is not listening.
	client := NewConstraintClient("http://127.0.0.1:1", zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
	assert.Contains(t, err.Error(), "failed to query controller")
}

func TestConstraintClient_Query_ContextCancelled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay so the context can be cancelled before the response.
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewConstraintClient(ts.URL, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	constraints, err := client.Query(ctx, "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
}

func TestConstraintClient_Query_InvalidURL(t *testing.T) {
	// A base URL with an invalid control character causes NewRequestWithContext to fail.
	client := NewConstraintClient("http://\x00invalid", zap.NewNop())
	constraints, err := client.Query(context.Background(), "test-ns", nil)
	require.Error(t, err)
	assert.Nil(t, constraints)
	assert.Contains(t, err.Error(), "failed to create request")
}

// ---------------------------------------------------------------------------
// sendResponse -- success path
// ---------------------------------------------------------------------------

func TestSendResponse_Success(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	w := httptest.NewRecorder()

	review := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			UID:     "test-uid",
			Allowed: true,
		},
	}
	handler.sendResponse(w, review)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var decoded map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Equal(t, "AdmissionReview", decoded["kind"])
	assert.Equal(t, "admission.k8s.io/v1", decoded["apiVersion"])
}

func TestSendResponse_SetsTypeMeta(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	w := httptest.NewRecorder()

	// Pass a review without TypeMeta set -- sendResponse should add it.
	review := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			UID:     "uid-123",
			Allowed: true,
			Warnings: []string{
				"[WARNING] Test warning - Fix it",
			},
		},
	}
	handler.sendResponse(w, review)

	assert.Equal(t, http.StatusOK, w.Code)

	var decoded admissionv1.AdmissionReview
	err := json.Unmarshal(w.Body.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Equal(t, "admission.k8s.io/v1", decoded.APIVersion)
	assert.Equal(t, "AdmissionReview", decoded.Kind)
	require.NotNil(t, decoded.Response)
	assert.Len(t, decoded.Response.Warnings, 1)
}

// ---------------------------------------------------------------------------
// processRequest -- nil request
// ---------------------------------------------------------------------------

func TestProcessRequest_NilRequest(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	response := handler.processRequest(context.Background(), nil)
	require.NotNil(t, response)
	assert.True(t, response.Allowed, "nil request must still be allowed (fail-open)")
}

// ---------------------------------------------------------------------------
// Handle -- body read error
// ---------------------------------------------------------------------------

func TestHandle_BodyReadError(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/validate", &errorReader{})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated read error")
}

// ---------------------------------------------------------------------------
// run() -- extracted main logic
// ---------------------------------------------------------------------------

func TestRun_FailsWithoutInClusterConfig(t *testing.T) {
	// run() calls rest.InClusterConfig() which will fail outside a cluster.
	// This exercises the error-return path for missing K8s config.
	cfg := runConfig{
		Addr:           ":0",
		ControllerURL:  "http://localhost:8080",
		Namespace:      "test-ns",
		SelfSignedMode: false,
	}

	err := run(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get in-cluster config")
}

func TestRun_FailsWithoutInClusterConfig_SelfSigned(t *testing.T) {
	cfg := runConfig{
		Addr:           ":0",
		ControllerURL:  "http://localhost:8080",
		Namespace:      "test-ns",
		SelfSignedMode: true,
	}

	err := run(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get in-cluster config")
}

// ---------------------------------------------------------------------------
// startServer() -- with fake clientset
// ---------------------------------------------------------------------------

func TestStartServer_SelfSigned_FileBasedCerts(t *testing.T) {
	certFile, keyFile := generateTempCertFiles(t, "localhost")

	cfg := runConfig{
		Addr:           fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		ControllerURL:  "http://localhost:8080",
		Namespace:      "test-ns",
		SelfSignedMode: false, // Not using CertManager
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
	}

	clientset := fake.NewSimpleClientset()
	logger := zap.NewNop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- startServer(cfg, clientset, logger)
	}()

	// Give the server time to start, then send signal to shut down.
	time.Sleep(300 * time.Millisecond)
	// Send SIGINT to ourselves to trigger shutdown.
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGINT))

	select {
	case err := <-errCh:
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("startServer did not return within timeout")
	}
}

func TestStartServer_SelfSignedMode(t *testing.T) {
	port := freePort(t)
	cfg := runConfig{
		Addr:           fmt.Sprintf("127.0.0.1:%d", port),
		ControllerURL:  "http://localhost:8080",
		Namespace:      "test-ns",
		SelfSignedMode: true,
	}

	clientset := fake.NewSimpleClientset()
	logger := zap.NewNop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- startServer(cfg, clientset, logger)
	}()

	// Wait for the server to start and become ready.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 2 * time.Second,
	}

	addr := cfg.Addr
	var lastErr error
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := httpClient.Get(fmt.Sprintf("https://%s/healthz", addr))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			lastErr = nil
			break
		}
	}
	require.NoError(t, lastErr, "server should become ready")

	// Verify healthz endpoint works.
	resp, err := httpClient.Get(fmt.Sprintf("https://%s/healthz", addr))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Send SIGINT to trigger shutdown.
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGINT))

	select {
	case err := <-errCh:
		if err != nil {
			assert.ErrorIs(t, err, http.ErrServerClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("startServer did not return within timeout")
	}
}

func TestStartServer_NoTLSConfig(t *testing.T) {
	cfg := runConfig{
		Addr:           ":0",
		ControllerURL:  "http://localhost:8080",
		Namespace:      "test-ns",
		SelfSignedMode: false,
		// No TLS cert files and no self-signed mode means no CertManager
	}

	clientset := fake.NewSimpleClientset()
	logger := zap.NewNop()

	err := startServer(cfg, clientset, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to configure TLS")
}

// ---------------------------------------------------------------------------
// Start -- errCh path: invalid cert file triggers ListenAndServeTLS error
// ---------------------------------------------------------------------------

func TestStart_InvalidCertFile_ReturnsError(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	srv := NewServer(ServerConfig{
		Addr:        fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
	}, handler, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := srv.Start(ctx)
	require.Error(t, err)
	// The error comes from ListenAndServeTLS failing to open the cert file.
	assert.Contains(t, err.Error(), "no such file")
}

// ---------------------------------------------------------------------------
// sendResponse -- marshal error path (use a ResponseWriter that tracks calls)
// ---------------------------------------------------------------------------

func TestSendResponse_MarshalError(t *testing.T) {
	logger := zap.NewNop()
	handler := NewAdmissionHandler(&mockQuerier{}, logger)

	w := httptest.NewRecorder()

	// Create a review with a Response.Result that contains raw extension
	// with an invalid json.RawMessage value. While json.RawMessage is just
	// bytes that get passed through, we can trigger a marshal error by
	// embedding a value that the JSON encoder cannot handle.
	review := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			UID:     "test-uid",
			Allowed: true,
			Result: &metav1.Status{
				Message: "ok",
			},
		},
	}
	// Override Object with a runtime.RawExtension containing intentionally broken content
	review.Response.Result.Details = &metav1.StatusDetails{
		Name: "test",
	}

	// This will succeed because all fields are valid - we need a different approach
	// to trigger marshal error. Use runtime.RawExtension with invalid content.
	review.Request = &admissionv1.AdmissionRequest{
		Object: runtime.RawExtension{
			Object: &unmarshalableObject{},
		},
	}

	handler.sendResponse(w, review)

	// The marshal should fail, resulting in a 500 error.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// unmarshalableObject implements runtime.Object but fails JSON marshaling.
type unmarshalableObject struct{}

func (u *unmarshalableObject) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }
func (u *unmarshalableObject) DeepCopyObject() runtime.Object   { return u }
func (u *unmarshalableObject) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("intentional marshal failure")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// generateTempCertFiles creates temporary TLS cert/key files and returns
// their paths. The certificate is self-signed and valid for the given
// serviceName DNS SAN.
func generateTempCertFiles(t *testing.T, serviceName string) (certPath, keyPath string) {
	t.Helper()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "tls.crt")
	keyFile := filepath.Join(tmpDir, "tls.key")

	client := fake.NewSimpleClientset()
	certCfg := webhook.CertManagerConfig{
		Mode:              webhook.CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       serviceName,
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := webhook.NewCertManager(client, certCfg, zap.NewNop())
	err := cm.EnsureCertificates(context.Background())
	require.NoError(t, err)

	_, certPEM, keyPEM := cm.GetCertificates()
	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))

	return certFile, keyFile
}

// freePort binds to port 0 to get a kernel-assigned free port and returns it.
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to get free port")
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}
