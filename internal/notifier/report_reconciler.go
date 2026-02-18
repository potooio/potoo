package notifier

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/requirements"
	"github.com/potooio/potoo/internal/types"
)

// ReportReconcilerOptions configures the ReportReconciler behavior.
type ReportReconcilerOptions struct {
	// DebounceDuration is the minimum time between reconciles for the same namespace.
	// Default: 10 seconds.
	DebounceDuration time.Duration

	// DefaultDetailLevel is the detail level for reports when not configured.
	// Default: DetailLevelSummary.
	DefaultDetailLevel types.DetailLevel

	// DefaultContact is shown in remediation steps.
	DefaultContact string

	// Workers is the number of concurrent workers processing namespace reconciles.
	// Default: 3.
	Workers int
}

// DefaultReportReconcilerOptions returns sensible defaults.
func DefaultReportReconcilerOptions() ReportReconcilerOptions {
	return ReportReconcilerOptions{
		DebounceDuration:   10 * time.Second,
		DefaultDetailLevel: types.DetailLevelSummary,
		DefaultContact:     "your platform team",
		Workers:            3,
	}
}

// ReportReconciler reconciles ConstraintReport CRDs based on indexer changes.
type ReportReconciler struct {
	logger             *zap.Logger
	client             client.Client
	idx                *indexer.Indexer
	remediationBuilder *RemediationBuilder
	evaluator          *requirements.Evaluator
	dynamicClient      dynamic.Interface
	opts               ReportReconcilerOptions
	policyRouter       *PolicyRouter

	mu                   sync.Mutex
	lastReconcile        map[string]time.Time
	pendingTriggers      map[string]bool
	clusterWideTriggered bool
}

// NewReportReconciler creates a new ReportReconciler.
// evaluator and dynClient may be nil; missing-resource detection is skipped if either is nil.
// policyRouter may be nil; detail level defaults to opts.DefaultDetailLevel.
func NewReportReconciler(
	k8sClient client.Client,
	idx *indexer.Indexer,
	logger *zap.Logger,
	opts ReportReconcilerOptions,
	evaluator *requirements.Evaluator,
	dynClient dynamic.Interface,
	policyRouter *PolicyRouter,
) *ReportReconciler {
	if opts.DebounceDuration == 0 {
		opts.DebounceDuration = 10 * time.Second
	}
	if opts.DefaultDetailLevel == "" {
		opts.DefaultDetailLevel = types.DetailLevelSummary
	}
	if opts.Workers == 0 {
		opts.Workers = 3
	}

	return &ReportReconciler{
		logger:             logger.Named("report-reconciler"),
		client:             k8sClient,
		idx:                idx,
		remediationBuilder: NewRemediationBuilder(opts.DefaultContact),
		evaluator:          evaluator,
		dynamicClient:      dynClient,
		opts:               opts,
		policyRouter:       policyRouter,
		lastReconcile:      make(map[string]time.Time),
		pendingTriggers:    make(map[string]bool),
	}
}

// Start begins the reconciliation loop. Blocks until context is cancelled.
func (rr *ReportReconciler) Start(ctx context.Context) error {
	rr.logger.Info("Starting report reconciler",
		zap.Duration("debounce", rr.opts.DebounceDuration),
		zap.Int("workers", rr.opts.Workers))

	workCh := make(chan string, 100)
	var wg sync.WaitGroup
	for i := 0; i < rr.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ns := range workCh {
				rr.reconcileWithDebounce(ctx, ns)
			}
		}()
	}

	// Tick to process pending triggers
	ticker := time.NewTicker(rr.opts.DebounceDuration / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			close(workCh)
			wg.Wait()
			rr.logger.Info("Report reconciler stopped")
			return nil
		case <-ticker.C:
			rr.processPendingTriggers(ctx, workCh)
		}
	}
}

// reconcileWithDebounce checks the debounce window for a namespace and reconciles
// if enough time has elapsed. Thread-safe per-namespace via locking.
func (rr *ReportReconciler) reconcileWithDebounce(ctx context.Context, ns string) {
	rr.mu.Lock()
	lastReconcile := rr.lastReconcile[ns]
	rr.mu.Unlock()

	if time.Since(lastReconcile) < rr.opts.DebounceDuration {
		// Re-queue for later
		rr.mu.Lock()
		rr.pendingTriggers[ns] = true
		rr.mu.Unlock()
		return
	}

	if err := rr.ReconcileNamespace(ctx, ns); err != nil {
		rr.logger.Error("Failed to reconcile report",
			zap.String("namespace", ns),
			zap.Error(err))
	} else {
		rr.mu.Lock()
		rr.lastReconcile[ns] = time.Now()
		rr.mu.Unlock()
	}
}

// OnIndexChange is the callback for indexer.OnChangeFunc.
func (rr *ReportReconciler) OnIndexChange(event indexer.IndexEvent) {
	c := event.Constraint

	// Trigger reconcile for all affected namespaces
	namespaces := append([]string{}, c.AffectedNamespaces...)
	if c.Namespace != "" {
		namespaces = append(namespaces, c.Namespace)
	}

	// Cluster-scoped constraint with no explicit affected namespaces:
	// mark for cluster-wide reconciliation.
	if c.Namespace == "" && len(namespaces) == 0 {
		rr.mu.Lock()
		rr.clusterWideTriggered = true
		rr.mu.Unlock()
		return
	}

	rr.mu.Lock()
	for _, ns := range namespaces {
		rr.pendingTriggers[ns] = true
	}
	rr.mu.Unlock()
}

// systemNamespaces are namespaces that never contain user workloads and can be
// skipped during cluster-wide reconciliation to reduce load.
var systemNamespaces = map[string]bool{
	"kube-system":       true,
	"kube-public":       true,
	"kube-node-lease":   true,
	"gatekeeper-system": true,
	"kyverno-system":    true,
	"potoo-system":      true,
}

// processPendingTriggers reconciles reports for pending namespaces by dispatching
// work items to the worker pool.
func (rr *ReportReconciler) processPendingTriggers(ctx context.Context, workCh chan<- string) {
	rr.mu.Lock()
	triggers := rr.pendingTriggers
	clusterWide := rr.clusterWideTriggered
	rr.pendingTriggers = make(map[string]bool)
	rr.clusterWideTriggered = false
	rr.mu.Unlock()

	// Cluster-wide trigger: list all namespaces and add them as triggers.
	if clusterWide && rr.dynamicClient != nil {
		nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
		list, err := rr.dynamicClient.Resource(nsGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			rr.logger.Error("Failed to list namespaces for cluster-wide reconcile", zap.Error(err))
		} else {
			for _, item := range list.Items {
				name := item.GetName()
				if !systemNamespaces[name] {
					triggers[name] = true
				}
			}
		}
	}

	for ns := range triggers {
		select {
		case workCh <- ns:
		default:
			// Channel full — re-queue for next tick
			rr.mu.Lock()
			rr.pendingTriggers[ns] = true
			rr.mu.Unlock()
		}
	}
}

// ReconcileNamespace updates or creates the ConstraintReport for a namespace.
func (rr *ReportReconciler) ReconcileNamespace(ctx context.Context, namespace string) error {
	constraints := rr.idx.ByNamespace(namespace)

	// Get or create the ConstraintReport
	report := &v1alpha1.ConstraintReport{}
	reportName := "constraints" // One report per namespace

	err := rr.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: reportName}, report)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		// Create new report
		report = &v1alpha1.ConstraintReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      reportName,
				Namespace: namespace,
			},
		}
	}

	// Update status
	report.Status = rr.buildReportStatus(constraints, namespace)

	// Create or update
	if report.ResourceVersion == "" {
		if err := rr.client.Create(ctx, report); err != nil {
			return err
		}
		rr.logger.Info("Created ConstraintReport",
			zap.String("namespace", namespace),
			zap.Int("constraints", len(constraints)))
	} else {
		if err := rr.client.Status().Update(ctx, report); err != nil {
			return err
		}
		rr.logger.Debug("Updated ConstraintReport",
			zap.String("namespace", namespace),
			zap.Int("constraints", len(constraints)))
	}

	return nil
}

// buildReportStatus builds the ConstraintReportStatus from constraints.
func (rr *ReportReconciler) buildReportStatus(constraints []types.Constraint, namespace string) v1alpha1.ConstraintReportStatus {
	now := metav1.Now()

	status := v1alpha1.ConstraintReportStatus{
		ConstraintCount: len(constraints),
		LastUpdated:     now,
	}

	// Count by severity and build entries
	var entries []v1alpha1.ConstraintEntry
	var machineEntries []v1alpha1.MachineConstraintEntry
	var allTags []string
	tagSet := make(map[string]bool)

	for _, c := range constraints {
		// Count by severity
		switch c.Severity {
		case types.SeverityCritical:
			status.CriticalCount++
		case types.SeverityWarning:
			status.WarningCount++
		case types.SeverityInfo:
			status.InfoCount++
		}

		// Build human-readable entry
		entry := v1alpha1.ConstraintEntry{
			Name:     rr.scopedName(c, namespace),
			Type:     string(c.ConstraintType),
			Severity: string(c.Severity),
			Message:  rr.scopedMessage(c, namespace),
			Source:   c.Source.Resource,
			LastSeen: now,
		}
		entries = append(entries, entry)

		// Build machine-readable entry
		machineEntry := rr.buildMachineEntry(c, namespace)
		machineEntries = append(machineEntries, machineEntry)

		// Collect tags
		for _, tag := range c.Tags {
			if !tagSet[tag] {
				tagSet[tag] = true
				allTags = append(allTags, tag)
			}
		}
	}

	// Sort entries by severity (critical first)
	sort.Slice(entries, func(i, j int) bool {
		return severityOrder(entries[i].Severity) < severityOrder(entries[j].Severity)
	})
	sort.Slice(machineEntries, func(i, j int) bool {
		return severityOrder(machineEntries[i].Severity) < severityOrder(machineEntries[j].Severity)
	})
	sort.Strings(allTags)

	status.Constraints = entries

	// Evaluate missing resources if evaluator is available.
	missingResources := rr.evaluateMissingResources(namespace)

	// Build machine-readable section
	status.MachineReadable = &v1alpha1.MachineReadableReport{
		SchemaVersion:    "1",
		GeneratedAt:      now,
		DetailLevel:      string(rr.effectiveDetailLevel()),
		Constraints:      machineEntries,
		Tags:             allTags,
		MissingResources: missingResources,
	}

	return status
}

// buildMachineEntry builds a MachineConstraintEntry from a Constraint.
func (rr *ReportReconciler) buildMachineEntry(c types.Constraint, viewerNamespace string) v1alpha1.MachineConstraintEntry {
	remediation := rr.remediationBuilder.Build(c)

	entry := v1alpha1.MachineConstraintEntry{
		UID:            string(c.UID),
		Name:           rr.scopedName(c, viewerNamespace),
		ConstraintType: string(c.ConstraintType),
		Severity:       string(c.Severity),
		Effect:         c.Effect,
		SourceRef: v1alpha1.ObjectReference{
			APIVersion: gvrToAPIVersion(c.Source),
			Kind:       gvrToKindName(c.Source),
			Name:       c.Name,
			Namespace:  c.Namespace,
		},
		Remediation:  remediation,
		Tags:         c.Tags,
		LastObserved: metav1.Now(),
	}

	// Extract metrics for resource constraints
	if c.ConstraintType == types.ConstraintTypeResourceLimit {
		entry.Metrics = rr.extractResourceMetrics(c)
	}

	return entry
}

// extractResourceMetrics extracts ResourceMetric map from constraint details.
func (rr *ReportReconciler) extractResourceMetrics(c types.Constraint) map[string]v1alpha1.ResourceMetric {
	if c.Details == nil {
		return nil
	}

	resources, ok := c.Details["resources"].(map[string]interface{})
	if !ok {
		return nil
	}

	metrics := make(map[string]v1alpha1.ResourceMetric)
	for name, infoRaw := range resources {
		info, ok := infoRaw.(map[string]interface{})
		if !ok {
			continue
		}

		metric := v1alpha1.ResourceMetric{
			Unit: guessUnit(name),
		}

		if hard, ok := info["hard"].(string); ok {
			metric.Hard = hard
		}
		if used, ok := info["used"].(string); ok {
			metric.Used = used
		}
		if percent, ok := info["percent"].(int); ok {
			metric.PercentUsed = float64(percent)
		} else if percentFloat, ok := info["percent"].(float64); ok {
			metric.PercentUsed = percentFloat
		}

		metrics[name] = metric
	}

	return metrics
}

// effectiveDetailLevel returns the detail level from the PolicyRouter if available,
// otherwise falls back to the configured default.
func (rr *ReportReconciler) effectiveDetailLevel() types.DetailLevel {
	if rr.policyRouter != nil {
		return rr.policyRouter.DetailLevel(rr.opts.DefaultDetailLevel)
	}
	return rr.opts.DefaultDetailLevel
}

// scopedName returns the constraint name respecting privacy rules.
func (rr *ReportReconciler) scopedName(c types.Constraint, viewerNamespace string) string {
	// At summary level, only show name if same namespace
	if rr.effectiveDetailLevel() == types.DetailLevelSummary {
		if c.Namespace != "" && c.Namespace != viewerNamespace {
			return "cluster-policy"
		}
	}
	return c.Name
}

// scopedMessage returns the summary respecting privacy rules.
func (rr *ReportReconciler) scopedMessage(c types.Constraint, viewerNamespace string) string {
	if rr.effectiveDetailLevel() == types.DetailLevelSummary {
		if c.Namespace != "" && c.Namespace != viewerNamespace {
			return genericSummary(c.ConstraintType)
		}
	}
	if c.Summary != "" {
		return c.Summary
	}
	return genericSummary(c.ConstraintType)
}

// severityOrder returns a sort order for severities (lower = more severe).
func severityOrder(severity string) int {
	switch severity {
	case "Critical":
		return 0
	case "Warning":
		return 1
	case "Info":
		return 2
	default:
		return 3
	}
}

// workloadGVRs are the GVRs scanned when evaluating missing resources per namespace.
var workloadGVRs = []schema.GroupVersionResource{
	{Group: "apps", Version: "v1", Resource: "deployments"},
	{Group: "apps", Version: "v1", Resource: "statefulsets"},
	{Group: "apps", Version: "v1", Resource: "daemonsets"},
}

const (
	evaluateTimeout          = 5 * time.Second
	maxWorkloadsPerReconcile = 100
)

// evaluateMissingResources runs the requirements evaluator over workloads in the
// namespace and returns MissingResourceEntry items for the report. Returns an empty
// slice (never nil) so the CRD always has the field present.
func (rr *ReportReconciler) evaluateMissingResources(namespace string) []v1alpha1.MissingResourceEntry {
	if rr.evaluator == nil || rr.dynamicClient == nil {
		return []v1alpha1.MissingResourceEntry{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), evaluateTimeout)
	defer cancel()

	var allMissing []v1alpha1.MissingResourceEntry

	for _, gvr := range workloadGVRs {
		list, err := rr.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{
			Limit: maxWorkloadsPerReconcile,
		})
		if err != nil {
			rr.logger.Warn("Failed to list workloads for missing-resource evaluation",
				zap.String("namespace", namespace),
				zap.String("gvr", gvr.String()),
				zap.Error(err))
			continue
		}

		for i := range list.Items {
			workload := &list.Items[i]
			constraints, err := rr.evaluator.Evaluate(ctx, workload)
			if err != nil {
				rr.logger.Debug("Failed to evaluate workload",
					zap.String("workload", workload.GetName()),
					zap.Error(err))
				continue
			}
			for _, c := range constraints {
				allMissing = append(allMissing, constraintToMissingResourceEntry(c, workload, rr.remediationBuilder))
			}
		}
	}

	if allMissing == nil {
		return []v1alpha1.MissingResourceEntry{}
	}
	return allMissing
}

// constraintToMissingResourceEntry converts a ConstraintTypeMissing constraint to a CRD MissingResourceEntry.
func constraintToMissingResourceEntry(c types.Constraint, workload *unstructured.Unstructured, rb *RemediationBuilder) v1alpha1.MissingResourceEntry {
	entry := v1alpha1.MissingResourceEntry{
		Severity: string(c.Severity),
	}

	if workload != nil {
		entry.ForWorkload = v1alpha1.WorkloadReference{
			Kind: workload.GetKind(),
			Name: workload.GetName(),
		}
	}

	if c.Details != nil {
		if v, ok := c.Details["expectedKind"].(string); ok {
			entry.ExpectedKind = v
		}
		if v, ok := c.Details["expectedAPIVersion"].(string); ok {
			entry.ExpectedAPIVersion = v
		}
		if v, ok := c.Details["reason"].(string); ok {
			entry.Reason = v
		}
	}

	if rb != nil {
		entry.Remediation = rb.Build(c)
	}

	return entry
}

// gvrToAPIVersion converts a GVR to an API version string.
func gvrToAPIVersion(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return gvr.Version
	}
	return fmt.Sprintf("%s/%s", gvr.Group, gvr.Version)
}

// gvrToKindName converts a GVR resource name to an approximate Kind name.
func gvrToKindName(gvr schema.GroupVersionResource) string {
	resource := gvr.Resource

	// Handle common plural to singular conversions
	switch resource {
	case "networkpolicies":
		return "NetworkPolicy"
	case "resourcequotas":
		return "ResourceQuota"
	case "limitranges":
		return "LimitRange"
	case "validatingwebhookconfigurations":
		return "ValidatingWebhookConfiguration"
	case "mutatingwebhookconfigurations":
		return "MutatingWebhookConfiguration"
	case "ciliumnetworkpolicies":
		return "CiliumNetworkPolicy"
	case "ciliumclusterwidenetworkpolicies":
		return "CiliumClusterwideNetworkPolicy"
	case "pods":
		return "Pod"
	case "deployments":
		return "Deployment"
	case "statefulsets":
		return "StatefulSet"
	default:
		// Generic: remove trailing 's' and capitalize
		if len(resource) > 1 && resource[len(resource)-1] == 's' {
			resource = resource[:len(resource)-1]
		}
		// Capitalize first letter
		if len(resource) > 0 {
			return string(resource[0]-32) + resource[1:]
		}
		return resource
	}
}
