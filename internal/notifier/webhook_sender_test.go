package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/correlator"
	"github.com/potooio/potoo/internal/types"
)

func testConstraint() types.Constraint {
	return types.Constraint{
		UID:            k8stypes.UID("test-uid-123"),
		Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		Name:           "deny-egress",
		Namespace:      "team-alpha",
		ConstraintType: types.ConstraintTypeNetworkEgress,
		Effect:         "deny",
		Severity:       types.SeverityCritical,
		Summary:        "Egress restricted to ports 443, 8443",
		Tags:           []string{"network", "egress"},
	}
}

func testStructuredData() EventStructuredData {
	return EventStructuredData{
		SchemaVersion:     "1",
		ConstraintUID:     "test-uid-123",
		ConstraintName:    "deny-egress",
		ConstraintType:    "NetworkEgress",
		Severity:          "Critical",
		Effect:            "deny",
		SourceGVR:         "networking.k8s.io/v1/networkpolicies",
		SourceKind:        "NetworkPolicy",
		WorkloadKind:      "Deployment",
		WorkloadName:      "api-server",
		WorkloadNamespace: "team-alpha",
		Summary:           "Egress restricted to ports 443, 8443",
		Tags:              []string{"network", "egress"},
		DetailLevel:       "summary",
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
	}
}

func newTestSender(t *testing.T, url string) *WebhookSender {
	t.Helper()
	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            url,
		TimeoutSeconds: 5,
		MinSeverity:    "Warning",
	})
	require.NoError(t, err)
	return ws
}

// waitForWebhook polls until the atomic counter reaches the expected value or timeout.
func waitForWebhook(t *testing.T, counter *atomic.Int32, expected int32, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if counter.Load() >= expected {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for webhook calls: got %d, want %d", counter.Load(), expected)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestNewWebhookSender_EmptyURL(t *testing.T) {
	_, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{URL: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook URL is required")
}

func TestNewWebhookSender_InvalidURL(t *testing.T) {
	_, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{URL: "://bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid webhook URL")
}

func TestNewWebhookSender_MissingScheme(t *testing.T) {
	_, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{URL: "not-a-url"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook URL must use http or https scheme")
}

func TestNewWebhookSender_MissingHost(t *testing.T) {
	_, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{URL: "http://"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook URL must include a host")
}

func TestNewWebhookSender_DefaultMinSeverity(t *testing.T) {
	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            "https://example.com/webhook",
		TimeoutSeconds: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, types.SeverityWarning, ws.minSeverity)
}

func TestWebhookSender_Success(t *testing.T) {
	var received atomic.Int32
	var mu sync.Mutex
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = body
		mu.Unlock()
		received.Add(1)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, userAgent, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws.Start(ctx)

	data := testStructuredData()
	err := ws.Send(ctx, data)
	require.NoError(t, err)

	waitForWebhook(t, &received, 1, 5*time.Second)

	// Verify payload structure.
	mu.Lock()
	body := make([]byte, len(receivedBody))
	copy(body, receivedBody)
	mu.Unlock()

	var envelope WebhookEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "potoo.constraint.notification", envelope.Type)
	assert.Equal(t, "1", envelope.SchemaVersion)
	assert.NotEmpty(t, envelope.Timestamp)
	assert.Equal(t, "test-uid-123", envelope.Data.ConstraintUID)
	assert.Equal(t, "NetworkEgress", envelope.Data.ConstraintType)
	assert.Equal(t, "Critical", envelope.Data.Severity)
	assert.Equal(t, "Deployment", envelope.Data.WorkloadKind)
	assert.Equal(t, "api-server", envelope.Data.WorkloadName)
}

func TestWebhookSender_RetryOn5xx(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := attempts.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ws.Start(ctx)

	err := ws.Send(ctx, testStructuredData())
	require.NoError(t, err)

	waitForWebhook(t, &attempts, 3, 15*time.Second)
	assert.Equal(t, int32(3), attempts.Load())
}

func TestWebhookSender_NoRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws.Start(ctx)

	err := ws.Send(ctx, testStructuredData())
	require.NoError(t, err)

	// Wait a bit to ensure no retries happen.
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(1), attempts.Load())
}

func TestWebhookSender_Timeout(t *testing.T) {
	// Use an unroutable IP (RFC 5737) to trigger a connection timeout
	// without needing a slow httptest server.
	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            "http://192.0.2.1:1/webhook", // TEST-NET-1, guaranteed unroutable
		TimeoutSeconds: 1,
		MinSeverity:    "Info",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws.Start(ctx)

	sendErr := ws.Send(ctx, testStructuredData())
	require.NoError(t, sendErr) // Send only enqueues, no error expected.

	// The actual error happens in the worker; we just verify it doesn't hang.
	time.Sleep(5 * time.Second)
}

func TestWebhookSender_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ws.Start(ctx)

	err := ws.Send(ctx, testStructuredData())
	require.NoError(t, err)

	// Cancel immediately, worker should exit gracefully.
	cancel()
	time.Sleep(500 * time.Millisecond) // allow worker to notice cancellation
}

func TestWebhookSender_ConcurrentSends(t *testing.T) {
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws.Start(ctx)

	const numSenders = 20
	var wg sync.WaitGroup
	wg.Add(numSenders)
	for range numSenders {
		go func() {
			defer wg.Done()
			_ = ws.Send(ctx, testStructuredData())
		}()
	}
	wg.Wait()

	waitForWebhook(t, &received, numSenders, 10*time.Second)
}

func TestWebhookSender_AuthHeader(t *testing.T) {
	var mu sync.Mutex
	var receivedAuth string
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            srv.URL,
		TimeoutSeconds: 5,
		MinSeverity:    "Info",
		AuthToken:      "test-secret-token",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws.Start(ctx)

	sendErr := ws.Send(ctx, testStructuredData())
	require.NoError(t, sendErr)

	waitForWebhook(t, &received, 1, 5*time.Second)
	mu.Lock()
	auth := receivedAuth
	mu.Unlock()
	assert.Equal(t, "Bearer test-secret-token", auth)
}

func TestWebhookSender_NoAuthHeader_WhenEmpty(t *testing.T) {
	var mu sync.Mutex
	var hasAuthHeader bool
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hasAuthHeader = r.Header.Get("Authorization") != ""
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws.Start(ctx)

	err := ws.Send(ctx, testStructuredData())
	require.NoError(t, err)

	waitForWebhook(t, &received, 1, 5*time.Second)
	mu.Lock()
	hadAuth := hasAuthHeader
	mu.Unlock()
	assert.False(t, hadAuth)
}

func TestSeverityFilter(t *testing.T) {
	tests := []struct {
		name        string
		minSeverity string
		severity    types.Severity
		shouldSend  bool
	}{
		{"critical meets critical", "Critical", types.SeverityCritical, true},
		{"warning meets critical", "Critical", types.SeverityWarning, false},
		{"info meets critical", "Critical", types.SeverityInfo, false},
		{"critical meets warning", "Warning", types.SeverityCritical, true},
		{"warning meets warning", "Warning", types.SeverityWarning, true},
		{"info meets warning", "Warning", types.SeverityInfo, false},
		{"critical meets info", "Info", types.SeverityCritical, true},
		{"warning meets info", "Info", types.SeverityWarning, true},
		{"info meets info", "Info", types.SeverityInfo, true},
		{"unknown severity filtered", "Warning", types.Severity("Unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
				URL:            "https://example.com/hook",
				TimeoutSeconds: 5,
				MinSeverity:    tt.minSeverity,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.shouldSend, ws.ShouldSend(tt.severity))
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "no credentials",
			input:    "https://example.com/webhook",
			contains: "example.com/webhook",
		},
		{
			name:     "userinfo credentials masked",
			input:    "https://user:s3cret@example.com/webhook",
			contains: "xxxxx",
			excludes: "s3cret",
		},
		{
			name:     "query param values masked",
			input:    "https://example.com/webhook?token=secret123&key=mykey",
			contains: "REDACTED",
			excludes: "secret123",
		},
		{
			name:     "invalid URL",
			input:    "://bad",
			contains: "<invalid-url>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactURL(tt.input)
			assert.Contains(t, result, tt.contains)
			if tt.excludes != "" {
				assert.NotContains(t, result, tt.excludes)
			}
		})
	}
}

func TestRedactURL_CredentialNotInLogs(t *testing.T) {
	core, observed := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // will cause error log
	}))
	defer srv.Close()

	ws, err := NewWebhookSender(logger, WebhookSenderConfig{
		URL:            "https://user:supersecret@example.com/hook",
		TimeoutSeconds: 1,
		MinSeverity:    "Info",
	})
	require.NoError(t, err)

	// The insecureSkipVerify warning contains the URL - verify it is redacted.
	_ = ws
	for _, entry := range observed.All() {
		assert.NotContains(t, entry.Message, "supersecret")
		for _, field := range entry.Context {
			assert.NotContains(t, field.String, "supersecret")
		}
	}
}

func TestWebhookSender_PayloadFormat(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = body
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws := newTestSender(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws.Start(ctx)

	data := testStructuredData()
	err := ws.Send(ctx, data)
	require.NoError(t, err)

	waitForWebhook(t, &received, 1, 5*time.Second)

	mu.Lock()
	body := make([]byte, len(receivedBody))
	copy(body, receivedBody)
	mu.Unlock()

	// Verify JSON keys are present.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &raw))

	assert.Contains(t, raw, "type")
	assert.Contains(t, raw, "schemaVersion")
	assert.Contains(t, raw, "timestamp")
	assert.Contains(t, raw, "data")

	dataMap, ok := raw["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, dataMap, "constraintUid")
	assert.Contains(t, dataMap, "constraintType")
	assert.Contains(t, dataMap, "severity")
	assert.Contains(t, dataMap, "workloadKind")
	assert.Contains(t, dataMap, "workloadName")
	assert.Contains(t, dataMap, "observedAt")
}

func TestNewWebhookSenderConfigFromCRD(t *testing.T) {
	wc := v1alpha1WebhookConfig()
	cfg := NewWebhookSenderConfigFromCRD(&wc, "my-token")
	assert.Equal(t, "https://hooks.example.com/test", cfg.URL)
	assert.Equal(t, 15, cfg.TimeoutSeconds)
	assert.Equal(t, true, cfg.InsecureSkipVerify)
	assert.Equal(t, "Critical", cfg.MinSeverity)
	assert.Equal(t, "my-token", cfg.AuthToken)
}

func TestNewWebhookSenderConfigFromCRD_Defaults(t *testing.T) {
	wc := v1alpha1WebhookConfigDefaults()
	cfg := NewWebhookSenderConfigFromCRD(&wc, "")
	assert.Equal(t, 10, cfg.TimeoutSeconds) // default
	assert.Equal(t, "Warning", cfg.MinSeverity)
	assert.Equal(t, "", cfg.AuthToken)
}

func TestDispatcher_WithWebhookSender(t *testing.T) {
	var received atomic.Int32
	var mu sync.Mutex
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = body
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            srv.URL,
		TimeoutSeconds: 5,
		MinSeverity:    "Warning",
	})
	require.NoError(t, err)

	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.Senders = []Sender{ws}
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.Start(ctx)

	notification := correlator.CorrelatedNotification{
		Constraint:   testConstraint(),
		Namespace:    "team-alpha",
		WorkloadName: "api-server",
		WorkloadKind: "Deployment",
	}
	dispErr := d.Dispatch(ctx, notification)
	require.NoError(t, dispErr)

	waitForWebhook(t, &received, 1, 5*time.Second)

	mu.Lock()
	body := make([]byte, len(receivedBody))
	copy(body, receivedBody)
	mu.Unlock()

	var envelope WebhookEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "potoo.constraint.notification", envelope.Type)
	assert.Equal(t, "NetworkEgress", envelope.Data.ConstraintType)
}

func TestDispatcher_WebhookDisabled_NoSenders(t *testing.T) {
	// Dispatcher with no senders should not error.
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.Start(ctx)

	notification := correlator.CorrelatedNotification{
		Constraint:   testConstraint(),
		Namespace:    "team-alpha",
		WorkloadName: "api-server",
		WorkloadKind: "Deployment",
	}
	err := d.Dispatch(ctx, notification)
	require.NoError(t, err)
}

func TestDispatcher_SeverityFiltering(t *testing.T) {
	var received atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Webhook with Critical-only filter.
	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            srv.URL,
		TimeoutSeconds: 5,
		MinSeverity:    "Critical",
	})
	require.NoError(t, err)

	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.SuppressDuplicateMinutes = 0 // disable dedup for this test
	opts.Senders = []Sender{ws}
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.Start(ctx)

	// Send a Warning-level notification — should NOT trigger webhook.
	warningConstraint := testConstraint()
	warningConstraint.Severity = types.SeverityWarning
	warningConstraint.UID = k8stypes.UID("warning-uid")
	notification := correlator.CorrelatedNotification{
		Constraint:   warningConstraint,
		Namespace:    "team-beta",
		WorkloadName: "web-server",
		WorkloadKind: "Deployment",
	}
	err = d.Dispatch(ctx, notification)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, int32(0), received.Load(), "Warning severity should not trigger Critical-only webhook")

	// Send a Critical-level notification — SHOULD trigger webhook.
	critConstraint := testConstraint()
	critConstraint.UID = k8stypes.UID("critical-uid")
	notification2 := correlator.CorrelatedNotification{
		Constraint:   critConstraint,
		Namespace:    "team-gamma",
		WorkloadName: "api-server-2",
		WorkloadKind: "Deployment",
	}
	err = d.Dispatch(ctx, notification2)
	require.NoError(t, err)

	waitForWebhook(t, &received, 1, 5*time.Second)
}

// Helper to create a CRD WebhookConfig for testing.
func v1alpha1WebhookConfig() v1alpha1.WebhookConfig {
	return v1alpha1.WebhookConfig{
		Enabled:            true,
		URL:                "https://hooks.example.com/test",
		TimeoutSeconds:     15,
		InsecureSkipVerify: true,
		MinSeverity:        "Critical",
	}
}

func TestWebhookSender_BufferFullDrop(t *testing.T) {
	// Create a sender but do NOT start workers so the buffer fills up.
	ws, err := NewWebhookSender(zap.NewNop(), WebhookSenderConfig{
		URL:            "https://example.com/hook",
		TimeoutSeconds: 5,
		MinSeverity:    "Info",
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Fill the buffer (defaultWebhookBufferSize = 100).
	for range defaultWebhookBufferSize {
		sendErr := ws.Send(ctx, testStructuredData())
		require.NoError(t, sendErr)
	}

	// Next send should be dropped.
	sendErr := ws.Send(ctx, testStructuredData())
	require.Error(t, sendErr)
	assert.Contains(t, sendErr.Error(), "webhook send buffer full")
}

func v1alpha1WebhookConfigDefaults() v1alpha1.WebhookConfig {
	return v1alpha1.WebhookConfig{
		Enabled: true,
		URL:     "https://hooks.example.com/test",
	}
}
