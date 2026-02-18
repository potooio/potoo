package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	"github.com/potooio/potoo/internal/annotations"
	"github.com/potooio/potoo/internal/indexer"
	internaltypes "github.com/potooio/potoo/internal/types"
)

const defaultNSWorkloadCacheTTL = 30 * time.Second

// namespaceWorkloadKinds are the workload kinds we resolve from namespace-level updates.
// Skip Pods (too churny), ReplicaSets (owned by Deployments), Jobs/CronJobs (short-lived).
var namespaceWorkloadKinds = []struct {
	Kind string
	GVR  schema.GroupVersionResource
}{
	{"Deployment", schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}},
	{"StatefulSet", schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}},
	{"DaemonSet", schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}},
}

// nsWorkloadCache caches workload lists per namespace to avoid API hammering during bursts.
type nsWorkloadCache struct {
	workloads []workloadKey
	fetchedAt time.Time
}

// WorkloadAnnotatorOptions configures the WorkloadAnnotator behavior.
type WorkloadAnnotatorOptions struct {
	// DebounceDuration is the minimum time between PATCHes for the same workload.
	// Default: 30 seconds.
	DebounceDuration time.Duration

	// CacheTTL is how long namespace workload lists are cached before re-fetching.
	// Default: 30 seconds.
	CacheTTL time.Duration

	// Workers is the number of concurrent workers processing annotation updates.
	// Default: 5.
	Workers int
}

// DefaultWorkloadAnnotatorOptions returns sensible defaults.
func DefaultWorkloadAnnotatorOptions() WorkloadAnnotatorOptions {
	return WorkloadAnnotatorOptions{
		DebounceDuration: 30 * time.Second,
		CacheTTL:         defaultNSWorkloadCacheTTL,
		Workers:          5,
	}
}

// workloadKey uniquely identifies a workload.
type workloadKey struct {
	Namespace string
	Kind      string
	Name      string
}

// pendingUpdate represents a debounced workload update.
type pendingUpdate struct {
	key       workloadKey
	scheduled time.Time
}

// WorkloadAnnotator watches the indexer for constraint changes and updates
// workload annotations with constraint summaries.
type WorkloadAnnotator struct {
	logger *zap.Logger
	client dynamic.Interface
	idx    *indexer.Indexer
	opts   WorkloadAnnotatorOptions

	mu        sync.Mutex
	lastPatch map[workloadKey]time.Time
	pending   chan pendingUpdate
	nsCache   map[string]nsWorkloadCache
}

// NewWorkloadAnnotator creates a new WorkloadAnnotator.
func NewWorkloadAnnotator(
	client dynamic.Interface,
	idx *indexer.Indexer,
	logger *zap.Logger,
	opts WorkloadAnnotatorOptions,
) *WorkloadAnnotator {
	if opts.DebounceDuration == 0 {
		opts.DebounceDuration = 30 * time.Second
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = defaultNSWorkloadCacheTTL
	}
	if opts.Workers == 0 {
		opts.Workers = 5
	}

	return &WorkloadAnnotator{
		logger:    logger.Named("workload-annotator"),
		client:    client,
		idx:       idx,
		opts:      opts,
		lastPatch: make(map[workloadKey]time.Time),
		pending:   make(chan pendingUpdate, 1000),
		nsCache:   make(map[string]nsWorkloadCache),
	}
}

// Start begins processing indexer changes. Blocks until context is cancelled.
func (wa *WorkloadAnnotator) Start(ctx context.Context) error {
	wa.logger.Info("Starting workload annotator",
		zap.Duration("debounce", wa.opts.DebounceDuration),
		zap.Duration("cache_ttl", wa.opts.CacheTTL),
		zap.Int("workers", wa.opts.Workers))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < wa.opts.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			wa.worker(ctx, workerID)
		}(i)
	}

	// Wait for context cancellation
	<-ctx.Done()
	close(wa.pending)
	wg.Wait()

	wa.logger.Info("Workload annotator stopped")
	return nil
}

// InvalidateCache removes the cached workload list for a namespace, forcing
// the next listNamespaceWorkloads call to re-fetch from the API server.
func (wa *WorkloadAnnotator) InvalidateCache(namespace string) {
	wa.mu.Lock()
	delete(wa.nsCache, namespace)
	wa.mu.Unlock()
}

// OnIndexChange is the callback for indexer.OnChangeFunc.
// It should be registered with the indexer at construction time.
func (wa *WorkloadAnnotator) OnIndexChange(event indexer.IndexEvent) {
	c := event.Constraint

	seen := make(map[string]struct{}, len(c.AffectedNamespaces)+1)
	for _, ns := range c.AffectedNamespaces {
		if _, ok := seen[ns]; !ok {
			seen[ns] = struct{}{}
			wa.InvalidateCache(ns)
			wa.queueNamespaceUpdate(ns)
		}
	}

	if c.Namespace != "" {
		if _, ok := seen[c.Namespace]; !ok {
			wa.InvalidateCache(c.Namespace)
			wa.queueNamespaceUpdate(c.Namespace)
		}
	}

	// Cluster-scoped constraint with no explicit affected namespaces:
	// queue a cluster-wide update so the worker lists all namespaces.
	if c.Namespace == "" && len(seen) == 0 {
		wa.queueClusterWideUpdate()
	}
}

// clusterWideSentinel is a special namespace value indicating that a cluster-wide
// update should list all namespaces and queue per-namespace updates.
const clusterWideSentinel = "\x00cluster-wide"

// queueNamespaceUpdate queues a namespace-level update. The worker resolves this
// into individual workload updates via listNamespaceWorkloads.
func (wa *WorkloadAnnotator) queueNamespaceUpdate(namespace string) {
	key := workloadKey{Namespace: namespace}

	select {
	case wa.pending <- pendingUpdate{key: key, scheduled: time.Now()}:
	default:
		wa.logger.Warn("Pending queue full, dropping update", zap.String("namespace", namespace))
	}
}

// queueClusterWideUpdate queues a sentinel update that causes the worker to list
// all namespaces and queue a per-namespace update for each.
func (wa *WorkloadAnnotator) queueClusterWideUpdate() {
	// Invalidate all cached namespace workload lists so workers re-fetch fresh data.
	wa.mu.Lock()
	wa.nsCache = make(map[string]nsWorkloadCache)
	wa.mu.Unlock()

	key := workloadKey{Namespace: clusterWideSentinel}

	select {
	case wa.pending <- pendingUpdate{key: key, scheduled: time.Now()}:
	default:
		wa.logger.Warn("Pending queue full, dropping cluster-wide update")
	}
}

// listNamespaceWorkloads returns workload keys for Deployments, StatefulSets, and
// DaemonSets in the given namespace. Results are cached for opts.CacheTTL.
// Returns an empty slice for empty namespace to avoid listing workloads across all namespaces.
func (wa *WorkloadAnnotator) listNamespaceWorkloads(ctx context.Context, namespace string) ([]workloadKey, error) {
	if namespace == "" {
		return nil, nil
	}

	wa.mu.Lock()
	cached, ok := wa.nsCache[namespace]
	wa.mu.Unlock()

	if ok && time.Since(cached.fetchedAt) < wa.opts.CacheTTL {
		return cached.workloads, nil
	}

	var result []workloadKey
	for _, wk := range namespaceWorkloadKinds {
		list, err := wa.client.Resource(wk.GVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			wa.logger.Warn("Failed to list workloads in namespace",
				zap.String("namespace", namespace),
				zap.String("kind", wk.Kind),
				zap.Error(err))
			continue
		}
		for _, item := range list.Items {
			result = append(result, workloadKey{
				Namespace: namespace,
				Kind:      wk.Kind,
				Name:      item.GetName(),
			})
		}
	}

	wa.mu.Lock()
	wa.nsCache[namespace] = nsWorkloadCache{workloads: result, fetchedAt: time.Now()}
	wa.mu.Unlock()

	return result, nil
}

// listAllNamespaces returns all namespace names from the cluster.
func (wa *WorkloadAnnotator) listAllNamespaces(ctx context.Context) ([]string, error) {
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	list, err := wa.client.Resource(nsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, item := range list.Items {
		namespaces = append(namespaces, item.GetName())
	}
	return namespaces, nil
}

// QueueWorkloadUpdate queues an annotation update for a specific workload.
func (wa *WorkloadAnnotator) QueueWorkloadUpdate(namespace, kind, name string) {
	key := workloadKey{Namespace: namespace, Kind: kind, Name: name}

	wa.mu.Lock()
	lastPatch := wa.lastPatch[key]
	wa.mu.Unlock()

	// Check debounce
	if time.Since(lastPatch) < wa.opts.DebounceDuration {
		wa.logger.Debug("Debouncing workload update",
			zap.String("namespace", namespace),
			zap.String("kind", kind),
			zap.String("name", name))
		return
	}

	select {
	case wa.pending <- pendingUpdate{key: key, scheduled: time.Now()}:
	default:
		wa.logger.Warn("Pending queue full, dropping workload update",
			zap.String("namespace", namespace),
			zap.String("kind", kind),
			zap.String("name", name))
	}
}

// worker processes pending updates.
func (wa *WorkloadAnnotator) worker(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-wa.pending:
			if !ok {
				return
			}
			wa.processUpdate(ctx, update)
		}
	}
}

// processUpdate handles a single workload annotation update.
func (wa *WorkloadAnnotator) processUpdate(ctx context.Context, update pendingUpdate) {
	key := update.key

	// Cluster-wide sentinel: list all namespaces and queue per-namespace updates.
	if key.Namespace == clusterWideSentinel {
		namespaces, err := wa.listAllNamespaces(ctx)
		if err != nil {
			wa.logger.Error("Failed to list namespaces for cluster-wide update", zap.Error(err))
			return
		}
		for _, ns := range namespaces {
			wa.queueNamespaceUpdate(ns)
		}
		return
	}

	// Namespace-level update: resolve to individual workload updates
	if key.Kind == "" || key.Name == "" {
		workloads, err := wa.listNamespaceWorkloads(ctx, key.Namespace)
		if err != nil {
			wa.logger.Error("Failed to list namespace workloads",
				zap.String("namespace", key.Namespace),
				zap.Error(err))
			return
		}
		for _, wk := range workloads {
			wa.QueueWorkloadUpdate(wk.Namespace, wk.Kind, wk.Name)
		}
		return
	}

	// Check debounce again
	wa.mu.Lock()
	lastPatch := wa.lastPatch[key]
	wa.mu.Unlock()

	if time.Since(lastPatch) < wa.opts.DebounceDuration {
		return
	}

	// Get constraints for this namespace
	constraints := wa.idx.ByNamespace(key.Namespace)

	// Build annotation patch
	patch := wa.buildAnnotationPatch(constraints)

	// Apply patch
	if err := wa.applyPatch(ctx, key, patch); err != nil {
		wa.logger.Error("Failed to patch workload annotations",
			zap.String("namespace", key.Namespace),
			zap.String("kind", key.Kind),
			zap.String("name", key.Name),
			zap.Error(err))
		return
	}

	// Update last patch time
	wa.mu.Lock()
	wa.lastPatch[key] = time.Now()
	wa.mu.Unlock()

	wa.logger.Debug("Updated workload annotations",
		zap.String("namespace", key.Namespace),
		zap.String("kind", key.Kind),
		zap.String("name", key.Name),
		zap.Int("constraints", len(constraints)))
}

// ConstraintSummary is a compact representation of a constraint for JSON serialization.
type ConstraintSummary struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Name     string `json:"name"`
	Source   string `json:"source"`
}

// buildAnnotationPatch creates the annotation values for a workload.
func (wa *WorkloadAnnotator) buildAnnotationPatch(constraints []internaltypes.Constraint) map[string]interface{} {
	if len(constraints) == 0 {
		// Return patch to remove annotations
		return map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					annotations.WorkloadStatus:        nil,
					annotations.WorkloadConstraints:   nil,
					annotations.WorkloadMaxSeverity:   nil,
					annotations.WorkloadCriticalCount: nil,
					annotations.WorkloadWarningCount:  nil,
					annotations.WorkloadInfoCount:     nil,
					annotations.WorkloadLastEvaluated: nil,
				},
			},
		}
	}

	// Count by severity
	criticalCount := 0
	warningCount := 0
	infoCount := 0
	maxSeverity := "none"

	var summaries []ConstraintSummary

	for _, c := range constraints {
		switch c.Severity {
		case internaltypes.SeverityCritical:
			criticalCount++
			maxSeverity = "critical"
		case internaltypes.SeverityWarning:
			warningCount++
			if maxSeverity != "critical" {
				maxSeverity = "warning"
			}
		case internaltypes.SeverityInfo:
			infoCount++
			if maxSeverity == "none" {
				maxSeverity = "info"
			}
		}

		summaries = append(summaries, ConstraintSummary{
			Type:     string(c.ConstraintType),
			Severity: string(c.Severity),
			Name:     c.Name,
			Source:   c.Source.Resource,
		})
	}

	// Build status string
	status := wa.buildStatusString(len(constraints), criticalCount, warningCount)

	// Serialize constraints to JSON
	constraintsJSON, _ := json.Marshal(summaries)

	return map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				annotations.WorkloadStatus:        status,
				annotations.WorkloadConstraints:   string(constraintsJSON),
				annotations.WorkloadMaxSeverity:   maxSeverity,
				annotations.WorkloadCriticalCount: strconv.Itoa(criticalCount),
				annotations.WorkloadWarningCount:  strconv.Itoa(warningCount),
				annotations.WorkloadInfoCount:     strconv.Itoa(infoCount),
				annotations.WorkloadLastEvaluated: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
}

// buildStatusString creates a human-readable status summary.
func (wa *WorkloadAnnotator) buildStatusString(total, critical, warning int) string {
	if total == 0 {
		return "No constraints"
	}

	parts := []string{}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critical))
	}
	if warning > 0 {
		parts = append(parts, fmt.Sprintf("%d warning", warning))
	}

	if len(parts) > 0 {
		return fmt.Sprintf("%d constraints (%s)", total, joinWithComma(parts))
	}
	return fmt.Sprintf("%d constraints", total)
}

// applyPatch applies the annotation patch to the workload.
func (wa *WorkloadAnnotator) applyPatch(ctx context.Context, key workloadKey, patch map[string]interface{}) error {
	// Get the GVR for the workload kind
	gvr, err := kindToGVR(key.Kind)
	if err != nil {
		return err
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	_, err = wa.client.Resource(gvr).Namespace(key.Namespace).Patch(
		ctx,
		key.Name,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)

	return err
}

// kindToGVR converts a Kubernetes Kind to a GroupVersionResource.
func kindToGVR(kind string) (schema.GroupVersionResource, error) {
	switch kind {
	case "Deployment":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, nil
	case "StatefulSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, nil
	case "DaemonSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, nil
	case "ReplicaSet":
		return schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, nil
	case "Job":
		return schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, nil
	case "CronJob":
		return schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, nil
	case "Pod":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, nil
	default:
		return schema.GroupVersionResource{}, fmt.Errorf("unsupported workload kind: %s", kind)
	}
}

// joinWithComma joins strings with ", ".
func joinWithComma(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}
