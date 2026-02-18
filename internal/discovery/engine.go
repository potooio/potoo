package discovery

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/adapters"
	"github.com/potooio/potoo/internal/adapters/generic"
	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

// defaultPolicyGroups are the built-in policy-related API groups.
// Resources in these groups are always treated as constraint-like.
var defaultPolicyGroups = map[string]bool{
	"networking.k8s.io":            true,
	"cilium.io":                    true,
	"constraints.gatekeeper.sh":    true,
	"kyverno.io":                   true,
	"security.istio.io":            true,
	"networking.istio.io":          true,
	"admissionregistration.k8s.io": true,
	"policy":                       true, // PodSecurityPolicy (deprecated but may exist)
}

// defaultPolicyNameHints are the built-in heuristic substrings.
var defaultPolicyNameHints = []string{
	"policy", "policies",
	"constraint", "constraints",
	"rule", "rules",
	"quota", "quotas",
	"limit", "limits",
	"authorization",
}

// IsPolicyAnnotation is the CRD annotation that marks a CRD as a policy source.
const IsPolicyAnnotation = "potoo.io/is-policy"

// profileState holds the runtime configuration for a single ConstraintProfile.
type profileState struct {
	gvr        schema.GroupVersionResource
	adapter    string
	fieldPaths *v1alpha1.FieldPaths
	severity   string
	enabled    bool
	stopCh     chan struct{} // per-profile stop channel for informer lifecycle
}

// Engine discovers constraint-like resources in the cluster and manages
// dynamic informers for them.
type Engine struct {
	logger          *zap.Logger
	discoveryClient discovery.DiscoveryInterface
	dynamicClient   dynamic.Interface
	registry        *adapters.Registry
	indexer         *indexer.Indexer
	genericAdapter  *generic.Adapter

	mu              sync.RWMutex
	watchedGVRs     map[schema.GroupVersionResource]bool
	informerFactory dynamicinformer.DynamicSharedInformerFactory
	stopCh          chan struct{}
	stopOnce        sync.Once
	ctx             context.Context // parent context from Start(), used by profile informers
	informers       map[schema.GroupVersionResource]cache.SharedIndexInformer

	rescanInterval time.Duration

	// Configurable heuristics (initialized from defaults, augmented by config).
	policyGroups map[string]bool
	nameHints    []string

	// ConstraintProfile state (protected by mu).
	profiles        map[string]*profileState
	annotatedCRDs   map[schema.GroupVersionResource]bool // cached CRD annotation results
	checkAnnotation bool                                 // whether to check CRD annotations during scan
}

// NewEngine creates a new discovery engine.
func NewEngine(
	logger *zap.Logger,
	discoveryClient discovery.DiscoveryInterface,
	dynamicClient dynamic.Interface,
	registry *adapters.Registry,
	idx *indexer.Indexer,
	rescanInterval time.Duration,
) *Engine {
	// Copy defaults so modifications don't affect the package-level vars.
	groups := make(map[string]bool, len(defaultPolicyGroups))
	for k, v := range defaultPolicyGroups {
		groups[k] = v
	}
	hints := make([]string, len(defaultPolicyNameHints))
	copy(hints, defaultPolicyNameHints)

	return &Engine{
		logger:          logger.Named("discovery"),
		discoveryClient: discoveryClient,
		dynamicClient:   dynamicClient,
		registry:        registry,
		indexer:         idx,
		genericAdapter:  generic.New(),
		watchedGVRs:     make(map[schema.GroupVersionResource]bool),
		informers:       make(map[schema.GroupVersionResource]cache.SharedIndexInformer),
		stopCh:          make(chan struct{}),
		rescanInterval:  rescanInterval,
		policyGroups:    groups,
		nameHints:       hints,
		profiles:        make(map[string]*profileState),
		annotatedCRDs:   make(map[schema.GroupVersionResource]bool),
		checkAnnotation: true,
	}
}

// SetAdditionalGroups adds extra API groups to the policy detection heuristic.
func (e *Engine) SetAdditionalGroups(groups []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, g := range groups {
		e.policyGroups[g] = true
	}
}

// SetAdditionalHints adds extra name hints to the policy detection heuristic.
func (e *Engine) SetAdditionalHints(hints []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nameHints = append(e.nameHints, hints...)
}

// SetCheckAnnotation controls whether the engine checks CRD annotations during scan.
func (e *Engine) SetCheckAnnotation(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checkAnnotation = enabled
}

// Start begins the discovery loop. It performs an initial scan, then
// rescans periodically. Call with a cancellable context.
func (e *Engine) Start(ctx context.Context) error {
	e.logger.Info("Starting discovery engine", zap.Duration("rescan_interval", e.rescanInterval))

	// Store parent context for profile informer event handlers.
	e.ctx = ctx

	// Initial scan
	if err := e.scan(ctx); err != nil {
		return err
	}

	// Periodic rescan for newly installed CRDs
	go func() {
		ticker := time.NewTicker(e.rescanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.scan(ctx); err != nil {
					e.logger.Error("Periodic rescan failed", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

// scan enumerates all API resources and identifies constraint-like ones.
func (e *Engine) scan(ctx context.Context) error {
	e.logger.Debug("Scanning for constraint-like resources")

	lists, err := e.discoveryClient.ServerPreferredResources()
	if err != nil {
		// ServerPreferredResources can return partial results with an error.
		// Log the error but continue with what we got.
		e.logger.Warn("Partial discovery result", zap.Error(err))
	}

	var discovered []schema.GroupVersionResource
	for _, list := range lists {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			e.logger.Warn("Failed to parse group version", zap.String("gv", list.GroupVersion), zap.Error(parseErr))
			continue
		}

		for _, r := range list.APIResources {
			// Skip sub-resources (e.g., pods/status, pods/log)
			if strings.Contains(r.Name, "/") {
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    gv.Group,
				Version:  gv.Version,
				Resource: r.Name,
			}

			if e.isConstraintLike(gvr, r.Name) {
				discovered = append(discovered, gvr)
			}
		}
	}

	// Check CRD annotations if enabled
	e.mu.RLock()
	checkAnnotation := e.checkAnnotation
	e.mu.RUnlock()
	if checkAnnotation {
		e.refreshAnnotatedCRDs(ctx)
	}

	// Start informers for newly discovered GVRs
	e.mu.Lock()
	defer e.mu.Unlock()

	e.logger.Info("Discovery scan complete",
		zap.Int("discovered", len(discovered)),
		zap.Int("previously_watched", len(e.watchedGVRs)),
	)

	// Build profile-suppressed GVR set: profiles with enabled=false exclude from discovery
	suppressed := make(map[schema.GroupVersionResource]bool)
	for _, ps := range e.profiles {
		if !ps.enabled {
			suppressed[ps.gvr] = true
		}
	}
	for _, gvr := range discovered {
		if suppressed[gvr] {
			continue
		}
		if !e.watchedGVRs[gvr] {
			e.logger.Info("New constraint-like resource discovered",
				zap.String("group", gvr.Group),
				zap.String("version", gvr.Version),
				zap.String("resource", gvr.Resource),
			)
			e.watchedGVRs[gvr] = true
			e.startInformer(ctx, gvr)
		}
	}

	return nil
}

// startInformer creates and starts a dynamic informer for the given GVR.
func (e *Engine) startInformer(ctx context.Context, gvr schema.GroupVersionResource) {
	// Create informer factory if not already created
	if e.informerFactory == nil {
		e.informerFactory = dynamicinformer.NewFilteredDynamicSharedInformerFactory(
			e.dynamicClient,
			30*time.Minute, // resync period
			"",             // all namespaces
			nil,            // no tweaks
		)
	}

	informer := e.informerFactory.ForResource(gvr).Informer()

	// Register event handlers
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.handleAdd(ctx, gvr, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			e.handleUpdate(ctx, gvr, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			e.handleDelete(ctx, gvr, obj)
		},
	}); err != nil {
		e.logger.Error("Failed to add event handler", zap.String("gvr", gvr.String()), zap.Error(err))
		return
	}

	e.informers[gvr] = informer

	// Start the informer in a goroutine
	go informer.Run(e.stopCh)

	e.logger.Debug("Started informer for GVR",
		zap.String("gvr", gvr.String()),
	)
}

// handleAdd processes a new object.
func (e *Engine) handleAdd(ctx context.Context, gvr schema.GroupVersionResource, obj interface{}) {
	// Skip if GVR has been suppressed (e.g., disabled by a ConstraintProfile)
	e.mu.RLock()
	watched := e.watchedGVRs[gvr]
	e.mu.RUnlock()
	if !watched {
		return
	}

	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		e.logger.Warn("Unexpected object type in AddFunc")
		return
	}

	constraints, err := e.parseObject(ctx, gvr, unstructuredObj)
	if err != nil {
		e.logger.Error("Failed to parse object",
			zap.String("gvr", gvr.String()),
			zap.String("name", unstructuredObj.GetName()),
			zap.String("namespace", unstructuredObj.GetNamespace()),
			zap.Error(err),
		)
		return
	}

	for _, c := range constraints {
		e.indexer.Upsert(c)
	}
}

// handleUpdate processes an updated object.
func (e *Engine) handleUpdate(ctx context.Context, gvr schema.GroupVersionResource, obj interface{}) {
	// Treat updates the same as adds - upsert will replace existing
	e.handleAdd(ctx, gvr, obj)
}

// handleDelete processes a deleted object.
// It parses the object to obtain constraint UIDs (which may differ from the
// source object UID when an adapter maps one object to multiple constraints,
// e.g. Kyverno rules) and removes each from the indexer.
func (e *Engine) handleDelete(ctx context.Context, gvr schema.GroupVersionResource, obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		// Handle deleted final state unknown (tombstone)
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			if unstructuredObj, ok = tombstone.Obj.(*unstructured.Unstructured); !ok {
				e.logger.Warn("Unexpected object type in tombstone")
				return
			}
		} else {
			e.logger.Warn("Unexpected object type in DeleteFunc")
			return
		}
	}

	// Parse the deleted object to discover all constraint UIDs it produced.
	// Adapters like Kyverno generate synthetic UIDs (one per rule), so
	// deleting only by source UID would miss them.
	constraints, err := e.parseObject(ctx, gvr, unstructuredObj)
	if err != nil || len(constraints) == 0 {
		// Fallback: delete by source object UID (works for 1:1 adapters).
		e.indexer.Delete(unstructuredObj.GetUID())
		return
	}

	for _, c := range constraints {
		e.indexer.Delete(c.UID)
	}
}

// parseObject routes the object to the appropriate adapter.
func (e *Engine) parseObject(ctx context.Context, gvr schema.GroupVersionResource, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	// Check if a ConstraintProfile provides config for this GVR
	e.mu.RLock()
	var profileCfg *profileState
	for _, ps := range e.profiles {
		if ps.enabled && ps.gvr == gvr {
			profileCfg = ps
			break
		}
	}
	e.mu.RUnlock()

	// If profile specifies a named adapter, try it
	if profileCfg != nil && profileCfg.adapter != "" && profileCfg.adapter != "generic" {
		adapter := e.registry.ForName(profileCfg.adapter)
		if adapter != nil {
			return adapter.Parse(ctx, obj)
		}
	}

	// Try specific GVR adapter first
	adapter := e.registry.ForGVR(gvr)
	if adapter != nil {
		return adapter.Parse(ctx, obj)
	}

	// Try group-based matching (for dynamic CRDs like Gatekeeper constraints)
	adapter = e.registry.ForGroup(gvr.Group)
	if adapter != nil {
		return adapter.Parse(ctx, obj)
	}

	// Fall back to generic adapter — with profile config if available
	if profileCfg != nil {
		cfg := generic.ParseConfig{
			FieldPaths:       profileCfg.fieldPaths,
			SeverityOverride: profileCfg.severity,
		}
		return e.genericAdapter.ParseWithConfig(ctx, obj, gvr, cfg)
	}
	return e.genericAdapter.ParseWithGVR(ctx, obj, gvr)
}

// isConstraintLike determines whether a GVR is likely a constraint/policy resource.
// Caller must NOT hold e.mu — this method acquires a read lock.
func (e *Engine) isConstraintLike(gvr schema.GroupVersionResource, resourceName string) bool {
	// Snapshot all mu-protected state under a single read lock for consistency.
	e.mu.RLock()
	groups := e.policyGroups
	hints := e.nameHints
	profileMatch := false
	for _, ps := range e.profiles {
		if ps.enabled && ps.gvr == gvr {
			profileMatch = true
			break
		}
	}
	annotated := e.annotatedCRDs[gvr]
	e.mu.RUnlock()

	// Check 1: Is this a known policy group?
	if groups[gvr.Group] {
		return true
	}

	// Check 2: Does the adapter registry already handle this GVR?
	if e.registry.ForGVR(gvr) != nil {
		return true
	}

	// Check 3: Native Kubernetes constraint resources
	if gvr.Group == "" {
		switch resourceName {
		case "resourcequotas", "limitranges":
			return true
		}
	}

	// Check 4: Heuristic — resource name contains policy-related substrings
	lower := strings.ToLower(resourceName)
	for _, hint := range hints {
		if strings.Contains(lower, hint) {
			return true
		}
	}

	// Check 5: ConstraintProfile CRDs that register additional types
	if profileMatch {
		return true
	}

	// Check 6: CRD annotation override
	return annotated
}

// WatchedGVRs returns the set of GVRs currently being watched.
func (e *Engine) WatchedGVRs() []schema.GroupVersionResource {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]schema.GroupVersionResource, 0, len(e.watchedGVRs))
	for gvr := range e.watchedGVRs {
		result = append(result, gvr)
	}
	return result
}

// RegisterProfile registers a ConstraintProfile, starting an informer for its
// GVR if enabled. Safe to call multiple times for the same profile (updates in place).
func (e *Engine) RegisterProfile(profile *v1alpha1.ConstraintProfile) error {
	name := profile.Name
	spec := profile.Spec
	gvr := schema.GroupVersionResource{
		Group:    spec.GVR.Group,
		Version:  spec.GVR.Version,
		Resource: spec.GVR.Resource,
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// If profile already exists, stop its old informer first
	if existing, ok := e.profiles[name]; ok {
		if existing.gvr != gvr || !spec.Enabled {
			e.stopProfileInformerLocked(existing)
		}
	}

	ps := &profileState{
		gvr:        gvr,
		adapter:    spec.Adapter,
		fieldPaths: spec.FieldPaths,
		severity:   spec.Severity,
		enabled:    spec.Enabled,
	}
	e.profiles[name] = ps

	if !spec.Enabled {
		// If explicitly disabled, stop any existing informer for this GVR
		// and clean up constraints
		e.stopGVRInformerLocked(gvr)
		return nil
	}

	// Start informer if not already watching this GVR
	if !e.watchedGVRs[gvr] {
		e.watchedGVRs[gvr] = true
		stopCh := make(chan struct{})
		ps.stopCh = stopCh
		e.startProfileInformer(gvr, stopCh)
		e.logger.Info("ConstraintProfile registered, started informer",
			zap.String("profile", name),
			zap.String("gvr", gvr.String()),
		)
	} else {
		e.logger.Info("ConstraintProfile registered, GVR already watched",
			zap.String("profile", name),
			zap.String("gvr", gvr.String()),
		)
	}

	return nil
}

// UnregisterProfile removes a ConstraintProfile and cleans up its resources.
func (e *Engine) UnregisterProfile(name string) {
	e.mu.Lock()

	ps, ok := e.profiles[name]
	if !ok {
		e.mu.Unlock()
		return
	}

	gvr := ps.gvr
	e.stopProfileInformerLocked(ps)
	delete(e.profiles, name)

	// Check if any other profile still needs this GVR
	needed := false
	for _, other := range e.profiles {
		if other.enabled && other.gvr == gvr {
			needed = true
			break
		}
	}

	if !needed {
		e.stopGVRInformerLocked(gvr)
	}

	e.mu.Unlock()

	// Clean up constraints outside the lock (indexer has its own lock)
	if !needed {
		n := e.indexer.DeleteBySource(gvr)
		e.logger.Info("ConstraintProfile unregistered, cleaned up constraints",
			zap.String("profile", name),
			zap.String("gvr", gvr.String()),
			zap.Int("removed", n),
		)
	} else {
		e.logger.Info("ConstraintProfile unregistered, GVR still needed by other profile",
			zap.String("profile", name),
			zap.String("gvr", gvr.String()),
		)
	}
}

// stopProfileInformerLocked closes a profile's stop channel. Caller must hold e.mu.
func (e *Engine) stopProfileInformerLocked(ps *profileState) {
	if ps.stopCh != nil {
		close(ps.stopCh)
		ps.stopCh = nil
	}
}

// stopGVRInformerLocked removes a GVR from the watched set and deletes its informer
// reference. Caller must hold e.mu.
func (e *Engine) stopGVRInformerLocked(gvr schema.GroupVersionResource) {
	delete(e.watchedGVRs, gvr)
	delete(e.informers, gvr)
}

// startProfileInformer creates and starts a dynamic informer with a profile-specific
// stop channel, allowing it to be stopped independently.
func (e *Engine) startProfileInformer(gvr schema.GroupVersionResource, stopCh chan struct{}) {
	if e.dynamicClient == nil {
		e.logger.Debug("Skipping profile informer start: no dynamic client", zap.String("gvr", gvr.String()))
		return
	}

	// Use a dedicated factory so the informer can be stopped independently.
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		e.dynamicClient,
		30*time.Minute, // resync period
		"",             // all namespaces
		nil,            // no tweaks
	)

	informer := factory.ForResource(gvr).Informer()

	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			e.handleAdd(ctx, gvr, obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			e.handleUpdate(ctx, gvr, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			e.handleDelete(ctx, gvr, obj)
		},
	}); err != nil {
		e.logger.Error("Failed to add event handler for profile informer",
			zap.String("gvr", gvr.String()), zap.Error(err))
		return
	}

	e.informers[gvr] = informer
	go informer.Run(stopCh)
}

// refreshAnnotatedCRDs lists all CRDs and caches which ones have the
// potoo.io/is-policy: "true" annotation.
func (e *Engine) refreshAnnotatedCRDs(ctx context.Context) {
	if e.dynamicClient == nil {
		return
	}

	// Recover from panics — the fake dynamic client in tests panics when
	// the CRD resource is not registered instead of returning an error.
	defer func() {
		if r := recover(); r != nil {
			e.logger.Debug("CRD annotation check unavailable", zap.Any("recovered", r))
		}
	}()

	crdGVR := schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}

	list, err := e.dynamicClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		e.logger.Debug("Failed to list CRDs for annotation check", zap.Error(err))
		return
	}

	annotated := make(map[schema.GroupVersionResource]bool)
	for i := range list.Items {
		crd := &list.Items[i]
		ann := crd.GetAnnotations()
		if ann == nil || ann[IsPolicyAnnotation] != "true" {
			continue
		}

		// Extract GVR from the CRD spec
		spec, ok := crd.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}
		group, _ := spec["group"].(string)
		names, ok := spec["names"].(map[string]interface{})
		if !ok {
			continue
		}
		plural, _ := names["plural"].(string)
		if group == "" || plural == "" {
			continue
		}

		// Use the first served version
		versions, ok := spec["versions"].([]interface{})
		if !ok || len(versions) == 0 {
			continue
		}
		firstVer, ok := versions[0].(map[string]interface{})
		if !ok {
			continue
		}
		version, _ := firstVer["name"].(string)
		if version == "" {
			continue
		}

		gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: plural}
		annotated[gvr] = true
	}

	e.mu.Lock()
	e.annotatedCRDs = annotated
	e.mu.Unlock()
}

// Stop stops all informers and the discovery engine. Safe to call multiple times.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		e.logger.Info("Stopping discovery engine")
		close(e.stopCh)

		// Also stop profile-managed informers
		e.mu.Lock()
		for _, ps := range e.profiles {
			e.stopProfileInformerLocked(ps)
		}
		e.mu.Unlock()
	})
}
