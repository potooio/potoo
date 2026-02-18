package correlator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/potooio/potoo/internal/hubble"
	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

const (
	// Rate limit: 100 events/second
	eventRateLimit = 100
	eventRateBurst = 200

	// Deduplication window: 5 minutes
	dedupeWindow = 5 * time.Minute

	// Channel buffer size
	notificationBuffer = 1000
)

// CorrelatedNotification pairs a Kubernetes event with a matching constraint.
type CorrelatedNotification struct {
	Event        *corev1.Event
	Constraint   types.Constraint
	Namespace    string
	WorkloadName string
	WorkloadKind string
}

// FlowDropNotification pairs a Hubble flow drop with a matching constraint.
type FlowDropNotification struct {
	FlowDrop   hubble.FlowDrop
	Constraint types.Constraint

	// Source pod information
	SourceNamespace string
	SourcePodName   string
	SourceWorkload  string
	SourceLabels    map[string]string

	// Destination pod information
	DestNamespace string
	DestPodName   string
	DestWorkload  string
	DestLabels    map[string]string

	// Connection information
	DestPort uint32
	Protocol string
}

// dedupeKey uniquely identifies an event-constraint pair.
type dedupeKey struct {
	eventUID      string
	constraintUID string
}

// Correlator watches Kubernetes Warning events and correlates them with constraints.
type Correlator struct {
	logger        *zap.Logger
	client        kubernetes.Interface
	indexer       *indexer.Indexer
	hubbleClient  *hubble.Client
	notifications chan CorrelatedNotification
	flowDrops     chan FlowDropNotification
	limiter       *rate.Limiter

	mu        sync.Mutex
	seenPairs map[dedupeKey]time.Time
}

// CorrelatorOptions configures the Correlator.
type CorrelatorOptions struct {
	// HubbleClient is optional; if nil, Hubble flow correlation is disabled.
	HubbleClient *hubble.Client
}

// New creates a new Correlator.
func New(idx *indexer.Indexer, client kubernetes.Interface, logger *zap.Logger) *Correlator {
	return NewWithOptions(idx, client, logger, CorrelatorOptions{})
}

// NewWithOptions creates a new Correlator with options.
func NewWithOptions(idx *indexer.Indexer, client kubernetes.Interface, logger *zap.Logger, opts CorrelatorOptions) *Correlator {
	return &Correlator{
		logger:        logger.Named("correlator"),
		client:        client,
		indexer:       idx,
		hubbleClient:  opts.HubbleClient,
		notifications: make(chan CorrelatedNotification, notificationBuffer),
		flowDrops:     make(chan FlowDropNotification, notificationBuffer),
		limiter:       rate.NewLimiter(eventRateLimit, eventRateBurst),
		seenPairs:     make(map[dedupeKey]time.Time),
	}
}

// Notifications returns the channel of correlated notifications.
func (c *Correlator) Notifications() <-chan CorrelatedNotification {
	return c.notifications
}

// FlowDropNotifications returns the channel of flow drop notifications.
func (c *Correlator) FlowDropNotifications() <-chan FlowDropNotification {
	return c.flowDrops
}

// Start begins watching events and correlating them. Blocks until context is cancelled.
func (c *Correlator) Start(ctx context.Context) error {
	c.logger.Info("Starting correlator")

	// Start dedupe cleaner
	go c.cleanupDedupeCache(ctx)

	// Start Hubble flow processor if configured
	if c.hubbleClient != nil {
		go c.processFlowDrops(ctx)
		c.logger.Info("Hubble flow correlation enabled")
	}

	for {
		if err := c.watchEvents(ctx); err != nil {
			if ctx.Err() != nil {
				c.logger.Info("Correlator stopped")
				close(c.notifications)
				close(c.flowDrops)
				return nil
			}
			c.logger.Error("Event watch failed, retrying", zap.Error(err))
			time.Sleep(5 * time.Second)
		}
	}
}

// watchEvents creates a watch on Warning events and processes them.
func (c *Correlator) watchEvents(ctx context.Context) error {
	watcher, err := c.client.CoreV1().Events("").Watch(ctx, metav1.ListOptions{
		FieldSelector: "type=Warning",
	})
	if err != nil {
		return err
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil // watch closed, will be retried
			}
			if event.Type == watch.Added || event.Type == watch.Modified {
				c.handleEvent(ctx, event.Object.(*corev1.Event))
			}
		}
	}
}

// handleEvent processes a single Kubernetes event.
func (c *Correlator) handleEvent(ctx context.Context, event *corev1.Event) {
	// Rate limit
	if !c.limiter.Allow() {
		c.logger.Debug("Event rate limited", zap.String("event", event.Name))
		return
	}

	involved := event.InvolvedObject
	ns := involved.Namespace
	if ns == "" {
		return // Skip cluster-scoped objects for now
	}

	// Query constraints for this namespace
	constraints := c.indexer.ByNamespace(ns)
	if len(constraints) == 0 {
		return
	}

	// Try to match each constraint
	for _, constraint := range constraints {
		// Atomic dedupe check-and-mark (avoids TOCTOU race between isDuplicate and markSeen)
		key := dedupeKey{
			eventUID:      string(event.UID),
			constraintUID: string(constraint.UID),
		}
		if !c.tryMarkSeen(key) {
			continue
		}

		// For now, emit all constraints in the namespace
		// Future: add smarter matching based on event message, reason, etc.
		notification := CorrelatedNotification{
			Event:        event.DeepCopy(),
			Constraint:   constraint,
			Namespace:    ns,
			WorkloadName: involved.Name,
			WorkloadKind: involved.Kind,
		}

		select {
		case c.notifications <- notification:
			// Already marked seen by tryMarkSeen above.
		case <-ctx.Done():
			return
		default:
			// Key is already marked seen — notification is intentionally dropped.
			// This is preferable to a TOCTOU race that could send duplicates.
			c.logger.Warn("Notification channel full, dropping event")
		}
	}
}

// tryMarkSeen atomically checks if this event-constraint pair was recently
// processed and, if not, marks it as seen. Returns true if this is a new
// (non-duplicate) pair that should be dispatched.
func (c *Correlator) tryMarkSeen(key dedupeKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seenAt, exists := c.seenPairs[key]; exists {
		if time.Since(seenAt) < dedupeWindow {
			return false
		}
	}
	c.seenPairs[key] = time.Now()
	return true
}

// cleanupDedupeCache periodically removes old entries from the dedupe cache.
func (c *Correlator) cleanupDedupeCache(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			cutoff := time.Now().Add(-dedupeWindow)
			for key, seenAt := range c.seenPairs {
				if seenAt.Before(cutoff) {
					delete(c.seenPairs, key)
				}
			}
			c.mu.Unlock()
		}
	}
}

// processFlowDrops reads from the Hubble client and correlates flow drops with constraints.
func (c *Correlator) processFlowDrops(ctx context.Context) {
	if c.hubbleClient == nil {
		return
	}

	drops := c.hubbleClient.DroppedFlows()
	for {
		select {
		case <-ctx.Done():
			return
		case drop, ok := <-drops:
			if !ok {
				c.logger.Info("Hubble flow channel closed")
				return
			}
			c.handleFlowDrop(ctx, drop)
		}
	}
}

// handleFlowDrop processes a single Hubble flow drop event.
func (c *Correlator) handleFlowDrop(ctx context.Context, drop hubble.FlowDrop) {
	// Only process policy-related drops
	if !drop.DropReason.IsPolicyDrop() {
		return
	}

	// Rate limit
	if !c.limiter.Allow() {
		c.logger.Debug("Flow drop rate limited",
			zap.String("source", drop.Source.PodName),
			zap.String("dest", drop.Destination.PodName))
		return
	}

	// Try to correlate with both source and destination namespaces
	namespaces := []string{}
	if drop.Source.Namespace != "" {
		namespaces = append(namespaces, drop.Source.Namespace)
	}
	if drop.Destination.Namespace != "" && drop.Destination.Namespace != drop.Source.Namespace {
		namespaces = append(namespaces, drop.Destination.Namespace)
	}

	if len(namespaces) == 0 {
		return
	}

	for _, ns := range namespaces {
		c.correlateFlowDropInNamespace(ctx, drop, ns)
	}
}

// correlateFlowDropInNamespace correlates a flow drop with constraints in a specific namespace.
func (c *Correlator) correlateFlowDropInNamespace(ctx context.Context, drop hubble.FlowDrop, namespace string) {
	// Query constraints for this namespace
	constraints := c.indexer.ByNamespace(namespace)
	if len(constraints) == 0 {
		return
	}

	// Determine which labels to match based on namespace
	var matchLabels map[string]string
	if namespace == drop.Source.Namespace {
		matchLabels = drop.Source.Labels
	} else {
		matchLabels = drop.Destination.Labels
	}

	// Try to find matching network policy constraints
	for _, constraint := range constraints {
		// Only correlate with network-related constraints
		if constraint.ConstraintType != types.ConstraintTypeNetworkIngress &&
			constraint.ConstraintType != types.ConstraintTypeNetworkEgress {
			continue
		}

		// Check if the constraint's workload selector matches the pod
		if !matchesSelector(constraint.WorkloadSelector, matchLabels) {
			continue
		}

		// Atomic dedupe check-and-mark using flow details as the key
		flowKey := fmt.Sprintf("flow:%s:%s:%s:%d",
			drop.Source.PodName, drop.Destination.PodName,
			drop.L4.Protocol, drop.L4.DestinationPort)
		key := dedupeKey{
			eventUID:      flowKey,
			constraintUID: string(constraint.UID),
		}
		if !c.tryMarkSeen(key) {
			continue
		}

		// Build the notification
		notification := FlowDropNotification{
			FlowDrop:        drop,
			Constraint:      constraint,
			SourceNamespace: drop.Source.Namespace,
			SourcePodName:   drop.Source.PodName,
			SourceLabels:    drop.Source.Labels,
			DestNamespace:   drop.Destination.Namespace,
			DestPodName:     drop.Destination.PodName,
			DestLabels:      drop.Destination.Labels,
			DestPort:        drop.L4.DestinationPort,
			Protocol:        string(drop.L4.Protocol),
		}

		// Extract workload names from workload refs
		if len(drop.Source.Workloads) > 0 {
			notification.SourceWorkload = drop.Source.Workloads[0].Name
		}
		if len(drop.Destination.Workloads) > 0 {
			notification.DestWorkload = drop.Destination.Workloads[0].Name
		}

		select {
		case c.flowDrops <- notification:
			// Already marked seen by tryMarkSeen above.
		case <-ctx.Done():
			return
		default:
			// Key is already marked seen — notification is intentionally dropped.
			// This is preferable to a TOCTOU race that could send duplicates.
			c.logger.Warn("Flow drop notification channel full")
		}
	}
}

// matchesSelector checks if the given labels match the selector.
func matchesSelector(selector *metav1.LabelSelector, lbls map[string]string) bool {
	return util.MatchesLabelSelector(selector, lbls)
}
