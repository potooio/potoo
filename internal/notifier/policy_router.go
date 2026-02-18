package notifier

import (
	"context"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/types"
)

const senderStopTimeout = 5 * time.Second

// PolicyRouter is a thread-safe store for active NotificationPolicies.
// It is updated by the NotificationPolicy controller and queried by the
// Dispatcher and ReportReconciler at notification time.
type PolicyRouter struct {
	mu       sync.RWMutex
	policies []v1alpha1.NotificationPolicy
	// senders holds dynamically-created senders keyed by policy name + channel type.
	senders map[string]*managedSender
	logger  *zap.Logger
	// ctx is the parent context for dynamically-created senders.
	ctx context.Context
	// senderFactory builds a WebhookSender from config. Injected for testing.
	senderFactory WebhookSenderFactory
}

// managedSender wraps a Sender with its cancel function for lifecycle management.
type managedSender struct {
	sender Sender
	cancel context.CancelFunc
}

// WebhookSenderFactory creates a WebhookSender from config. Allows test injection.
type WebhookSenderFactory func(logger *zap.Logger, cfg WebhookSenderConfig) (*WebhookSender, error)

// NewPolicyRouter creates a new PolicyRouter. The initial context is
// context.Background(); call SetContext to upgrade it to the manager's
// context once available. This avoids a nil-ctx race if the NotificationPolicy
// controller reconciles before the lifecycle runnable starts.
func NewPolicyRouter(logger *zap.Logger) *PolicyRouter {
	return &PolicyRouter{
		senders:       make(map[string]*managedSender),
		logger:        logger.Named("policy-router"),
		senderFactory: NewWebhookSender,
		ctx:           context.Background(),
	}
}

// SetContext stores the parent context used to derive sender contexts.
// Must be called before Update.
func (pr *PolicyRouter) SetContext(ctx context.Context) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.ctx = ctx
}

// Update replaces the active policy set. It diffs old vs new sender configs
// to avoid unnecessary sender churn: only senders whose configuration changed
// are stopped and recreated.
func (pr *PolicyRouter) Update(policies []v1alpha1.NotificationPolicy, authTokens map[string]string) {
	// Sort policies alphabetically by name for deterministic ordering.
	sorted := make([]v1alpha1.NotificationPolicy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Build desired sender set from new policies.
	desired := make(map[string]WebhookSenderConfig)
	for _, p := range sorted {
		if p.Spec.Channels.Webhook != nil && p.Spec.Channels.Webhook.Enabled {
			key := senderKey(p.Name, "webhook")
			token := ""
			if ref := p.Spec.Channels.Webhook.AuthSecretRef; ref != nil {
				token = authTokens[p.Name]
			}
			desired[key] = NewWebhookSenderConfigFromCRD(p.Spec.Channels.Webhook, token)
		}
		if p.Spec.Channels.Slack != nil && p.Spec.Channels.Slack.Enabled {
			pr.logger.Warn("Slack channel enabled in NotificationPolicy but no Slack sender is implemented; skipping",
				zap.String("policy", p.Name))
		}
	}

	// Stop senders that are no longer needed or whose config changed.
	for key, ms := range pr.senders {
		newCfg, exists := desired[key]
		if !exists {
			pr.stopSender(key, ms)
			delete(pr.senders, key)
			continue
		}
		// Check if config changed by comparing key fields.
		if ws, ok := ms.sender.(*WebhookSender); ok {
			if ws.url != newCfg.URL || ws.authToken != newCfg.AuthToken ||
				string(ws.minSeverity) != newCfg.MinSeverity {
				pr.stopSender(key, ms)
				delete(pr.senders, key)
			} else {
				// Config unchanged — keep existing sender, remove from desired.
				delete(desired, key)
			}
		}
	}

	// Create new senders for remaining desired entries.
	for key, cfg := range desired {
		ws, err := pr.senderFactory(pr.logger, cfg)
		if err != nil {
			pr.logger.Error("Failed to create webhook sender from NotificationPolicy",
				zap.String("key", key), zap.Error(err))
			continue
		}
		// Each sender gets its own derived context so it can be stopped independently.
		senderCtx, senderCancel := context.WithCancel(pr.ctx)
		ws.Start(senderCtx)
		pr.senders[key] = &managedSender{sender: ws, cancel: senderCancel}
		pr.logger.Info("Created webhook sender from NotificationPolicy",
			zap.String("key", key), zap.String("url", RedactURL(cfg.URL)))
	}

	pr.policies = sorted
}

// stopSender cancels the sender's context and waits for it to drain,
// with a timeout to prevent indefinite blocking.
func (pr *PolicyRouter) stopSender(key string, ms *managedSender) {
	ms.cancel()
	if ws, ok := ms.sender.(*WebhookSender); ok {
		done := make(chan struct{})
		go func() {
			ws.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(senderStopTimeout):
			pr.logger.Warn("Sender did not stop within timeout", zap.String("key", key))
		}
	}
	pr.logger.Info("Stopped sender", zap.String("key", key))
}

// Policies returns a snapshot of active policies. Thread-safe.
func (pr *PolicyRouter) Policies() []v1alpha1.NotificationPolicy {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	out := make([]v1alpha1.NotificationPolicy, len(pr.policies))
	copy(out, pr.policies)
	return out
}

// DetailLevel returns the developer-scope detail level from the first
// alphabetically-ordered policy, or the fallback if no policies exist.
// When multiple policies exist, the first policy's detail level is used
// for K8s Events and ConstraintReports (developer-facing channels).
func (pr *PolicyRouter) DetailLevel(fallback types.DetailLevel) types.DetailLevel {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.policies) == 0 {
		return fallback
	}
	level := types.DetailLevel(pr.policies[0].Spec.DeveloperScope.MaxDetailLevel)
	if level == "" {
		return fallback
	}
	return level
}

// SendersForPolicies returns all dynamically-created senders across all active
// policies. Thread-safe. The returned slice is a snapshot.
func (pr *PolicyRouter) SendersForPolicies() []Sender {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.senders) == 0 {
		return nil
	}
	out := make([]Sender, 0, len(pr.senders))
	for _, ms := range pr.senders {
		out = append(out, ms.sender)
	}
	return out
}

// Contact returns the developer-scope contact from the first policy,
// or empty string if no policies exist.
func (pr *PolicyRouter) Contact() string {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.policies) == 0 {
		return ""
	}
	return pr.policies[0].Spec.DeveloperScope.Contact
}

// Close stops all dynamically-created senders.
func (pr *PolicyRouter) Close() {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	for key, ms := range pr.senders {
		pr.stopSender(key, ms)
	}
	pr.senders = make(map[string]*managedSender)
}

// senderKey builds a unique key for a sender within a policy.
func senderKey(policyName, channelType string) string {
	return policyName + "/" + channelType
}
