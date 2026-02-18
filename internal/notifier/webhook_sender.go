package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/types"
)

const (
	defaultWebhookTimeout    = 10 * time.Second
	defaultWebhookWorkers    = 3
	defaultWebhookBufferSize = 100
	maxRetries               = 2
	userAgent                = "potoo-controller/v1"
)

// WebhookEnvelope is the JSON payload POSTed to webhook endpoints.
type WebhookEnvelope struct {
	// Type identifies the notification kind.
	Type string `json:"type"`
	// SchemaVersion allows consumers to detect breaking changes.
	SchemaVersion string `json:"schemaVersion"`
	// Timestamp is the RFC3339 time the notification was sent.
	Timestamp string `json:"timestamp"`
	// Data contains the full constraint notification payload.
	Data EventStructuredData `json:"data"`
}

// webhookWork is an internal message sent to the worker pool.
type webhookWork struct {
	ctx      context.Context
	envelope WebhookEnvelope
}

// WebhookSender implements the Sender interface for generic HTTP POST webhooks.
type WebhookSender struct {
	httpClient  *http.Client
	logger      *zap.Logger
	url         string
	authToken   string
	minSeverity types.Severity
	sendCh      chan webhookWork
	wg          sync.WaitGroup
}

// WebhookSenderConfig holds the configuration for creating a WebhookSender.
type WebhookSenderConfig struct {
	URL                string
	TimeoutSeconds     int
	InsecureSkipVerify bool
	MinSeverity        string
	// AuthToken is a pre-resolved bearer token from Secret. Stored at
	// construction time — Secret rotation requires a controller restart.
	AuthToken string
}

// NewWebhookSenderConfigFromCRD converts a v1alpha1.WebhookConfig to a WebhookSenderConfig.
// The authToken must be resolved separately from the K8s Secret.
func NewWebhookSenderConfigFromCRD(cfg *v1alpha1.WebhookConfig, authToken string) WebhookSenderConfig {
	timeout := cfg.TimeoutSeconds
	if timeout == 0 {
		timeout = 10
	}
	minSev := cfg.MinSeverity
	if minSev == "" {
		minSev = "Warning"
	}
	return WebhookSenderConfig{
		URL:                cfg.URL,
		TimeoutSeconds:     timeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinSeverity:        minSev,
		AuthToken:          authToken,
	}
}

// NewWebhookSender creates a WebhookSender. Returns an error if the URL is invalid.
func NewWebhookSender(logger *zap.Logger, cfg WebhookSenderConfig) (*WebhookSender, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("webhook URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("webhook URL must include a host")
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = defaultWebhookTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-configured
		logger.Warn("Webhook TLS certificate verification is disabled — this is insecure",
			zap.String("url", RedactURL(cfg.URL)))
	}

	minSev := types.Severity(cfg.MinSeverity)
	if minSev == "" {
		minSev = types.SeverityWarning
	}

	return &WebhookSender{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		logger:      logger.Named("webhook-sender"),
		url:         cfg.URL,
		authToken:   cfg.AuthToken,
		minSeverity: minSev,
		sendCh:      make(chan webhookWork, defaultWebhookBufferSize),
	}, nil
}

// Name implements Sender.
func (ws *WebhookSender) Name() string { return "webhook" }

// ShouldSend implements Sender. Returns true if the notification severity meets the minimum threshold.
func (ws *WebhookSender) ShouldSend(severity types.Severity) bool {
	return severityRank(severity) >= severityRank(ws.minSeverity)
}

// Start implements Sender. Launches background workers to drain the send channel.
func (ws *WebhookSender) Start(ctx context.Context) {
	for range defaultWebhookWorkers {
		ws.wg.Add(1)
		go ws.worker(ctx)
	}
	ws.logger.Info("Webhook sender started",
		zap.String("url", RedactURL(ws.url)),
		zap.Int("workers", defaultWebhookWorkers),
		zap.String("min_severity", string(ws.minSeverity)),
	)
}

// Close waits for all workers to finish draining queued notifications.
// Call after the context passed to Start is cancelled.
func (ws *WebhookSender) Close() {
	ws.wg.Wait()
}

// Send implements Sender. Enqueues the notification for async delivery.
func (ws *WebhookSender) Send(ctx context.Context, data EventStructuredData) error {
	envelope := WebhookEnvelope{
		Type:          "potoo.constraint.notification",
		SchemaVersion: "1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Data:          data,
	}

	select {
	case ws.sendCh <- webhookWork{ctx: ctx, envelope: envelope}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		webhookSendTotal.WithLabelValues("dropped").Inc()
		ws.logger.Warn("Webhook send buffer full, dropping notification",
			zap.String("constraint", data.ConstraintName))
		return fmt.Errorf("webhook send buffer full")
	}
}

// worker drains the send channel and delivers notifications.
// On context cancellation, it drains remaining buffered items before exiting.
func (ws *WebhookSender) worker(ctx context.Context) {
	defer ws.wg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain remaining buffered items before exiting.
			for {
				select {
				case work := <-ws.sendCh:
					drainCtx, cancel := context.WithTimeout(context.Background(), ws.httpClient.Timeout)
					if err := ws.doSend(drainCtx, work.envelope); err != nil {
						ws.logger.Warn("Webhook send failed during shutdown drain",
							zap.String("url", RedactURL(ws.url)),
							zap.Error(err),
						)
					}
					cancel()
				default:
					return
				}
			}
		case work, ok := <-ws.sendCh:
			if !ok {
				return
			}
			if err := ws.doSend(work.ctx, work.envelope); err != nil {
				ws.logger.Error("Webhook send failed",
					zap.String("url", RedactURL(ws.url)),
					zap.Error(err),
				)
			}
		}
	}
}

// doSend performs the HTTP POST with retry logic.
func (ws *WebhookSender) doSend(ctx context.Context, envelope WebhookEnvelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		webhookSendTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	var lastErr error
	for attempt := range maxRetries + 1 {
		if attempt > 0 {
			// Check context before retrying.
			select {
			case <-ctx.Done():
				webhookSendTotal.WithLabelValues("error").Inc()
				return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			default:
			}
			// Linear backoff: 1s, 2s.
			backoff := time.Duration(attempt) * time.Second
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				webhookSendTotal.WithLabelValues("error").Inc()
				return fmt.Errorf("context cancelled during backoff: %w", ctx.Err())
			}
			webhookSendTotal.WithLabelValues("retry").Inc()
		}

		lastErr = ws.doPost(ctx, body)
		if lastErr == nil {
			return nil
		}

		// Only retry on transient errors (5xx, connection issues).
		if !isRetryable(lastErr) {
			webhookSendTotal.WithLabelValues("error").Inc()
			return lastErr
		}

		ws.logger.Debug("Webhook send transient failure, will retry",
			zap.Int("attempt", attempt+1),
			zap.Error(lastErr),
		)
	}

	webhookSendTotal.WithLabelValues("error").Inc()
	return fmt.Errorf("webhook send failed after %d attempts: %w", maxRetries+1, lastErr)
}

// doPost executes a single HTTP POST request.
func (ws *WebhookSender) doPost(ctx context.Context, body []byte) error {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ws.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if ws.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+ws.authToken)
	}

	resp, err := ws.httpClient.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		webhookSendDuration.WithLabelValues("error").Observe(duration)
		return &webhookError{err: err, retryable: true}
	}
	defer func() {
		// Drain and close body to reuse connections.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		webhookSendTotal.WithLabelValues("success").Inc()
		webhookSendDuration.WithLabelValues("success").Observe(duration)
		return nil
	}

	webhookSendDuration.WithLabelValues("error").Observe(duration)
	retryable := resp.StatusCode >= 500
	return &webhookError{
		err:       fmt.Errorf("webhook returned HTTP %d", resp.StatusCode),
		retryable: retryable,
	}
}

// webhookError wraps an error with a retryable flag.
type webhookError struct {
	err       error
	retryable bool
}

func (e *webhookError) Error() string { return e.err.Error() }
func (e *webhookError) Unwrap() error { return e.err }

// isRetryable returns true if the error is a transient failure worth retrying.
func isRetryable(err error) bool {
	var we *webhookError
	if errors.As(err, &we) {
		return we.retryable
	}
	// Unknown errors (connection refused, DNS, etc.) are retryable.
	return true
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 3
	case types.SeverityWarning:
		return 2
	case types.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// RedactURL masks credentials in a URL for safe logging.
// It redacts userinfo passwords and query parameter values.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	// Redact userinfo password.
	redacted := u.Redacted()
	// Also redact query parameter values (e.g., ?token=secret).
	if u.RawQuery != "" {
		q := u.Query()
		for key := range q {
			q.Set(key, "REDACTED")
		}
		// Re-parse the redacted URL to set query params.
		r, err := url.Parse(redacted)
		if err != nil {
			return redacted
		}
		r.RawQuery = q.Encode()
		return r.String()
	}
	return redacted
}
