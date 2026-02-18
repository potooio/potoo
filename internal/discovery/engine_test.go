package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/adapters"
	"github.com/potooio/potoo/internal/adapters/networkpolicy"
	"github.com/potooio/potoo/internal/indexer"
	internaltypes "github.com/potooio/potoo/internal/types"
)

// mockDiscoveryClient embeds FakeDiscovery and overrides ServerPreferredResources.
type mockDiscoveryClient struct {
	*fakediscovery.FakeDiscovery
	mu        sync.Mutex
	resources []*metav1.APIResourceList
	scanErr   error
}

func (m *mockDiscoveryClient) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resources, m.scanErr
}

func (m *mockDiscoveryClient) setScanErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanErr = err
}

func newMockDiscovery(resources []*metav1.APIResourceList) *mockDiscoveryClient {
	fakeClient := fake.NewSimpleClientset()
	return &mockDiscoveryClient{
		FakeDiscovery: fakeClient.Discovery().(*fakediscovery.FakeDiscovery),
		resources:     resources,
	}
}

func setupTestEngine(t *testing.T) (*Engine, *indexer.Indexer) {
	t.Helper()
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()
	npAdapter := networkpolicy.New()
	err := registry.Register(npAdapter)
	require.NoError(t, err)

	engine := NewEngine(
		zap.NewNop(),
		nil, // no discovery client for unit tests
		nil, // no dynamic client for unit tests
		registry,
		idx,
		5*time.Minute,
	)
	return engine, idx
}

func TestNewEngine(t *testing.T) {
	engine, _ := setupTestEngine(t)

	require.NotNil(t, engine)
	assert.NotNil(t, engine.logger)
	assert.NotNil(t, engine.registry)
	assert.NotNil(t, engine.indexer)
	assert.NotNil(t, engine.genericAdapter)
	assert.NotNil(t, engine.watchedGVRs)
	assert.NotNil(t, engine.informers)
	assert.NotNil(t, engine.stopCh)
	assert.Equal(t, 5*time.Minute, engine.rescanInterval)
}

func TestWatchedGVRs_Empty(t *testing.T) {
	engine, _ := setupTestEngine(t)

	gvrs := engine.WatchedGVRs()
	assert.Empty(t, gvrs)
}

func TestWatchedGVRs_AfterManualAdd(t *testing.T) {
	engine, _ := setupTestEngine(t)

	// Manually add a watched GVR
	engine.mu.Lock()
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	engine.watchedGVRs[gvr] = true
	engine.mu.Unlock()

	gvrs := engine.WatchedGVRs()
	require.Len(t, gvrs, 1)
	assert.Equal(t, gvr, gvrs[0])
}

func TestStop(t *testing.T) {
	engine, _ := setupTestEngine(t)

	// Stop should not panic
	engine.Stop()

	// Verify stopCh is closed
	select {
	case <-engine.stopCh:
		// Expected - channel is closed
	default:
		t.Fatal("stopCh should be closed after Stop()")
	}
}

func TestIsConstraintLike(t *testing.T) {
	engine, _ := setupTestEngine(t)

	tests := []struct {
		name         string
		gvr          schema.GroupVersionResource
		resourceName string
		expected     bool
	}{
		{
			name:         "known policy group networking.k8s.io",
			gvr:          schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			resourceName: "networkpolicies",
			expected:     true,
		},
		{
			name:         "known policy group cilium.io",
			gvr:          schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
			resourceName: "ciliumnetworkpolicies",
			expected:     true,
		},
		{
			name:         "known policy group constraints.gatekeeper.sh",
			gvr:          schema.GroupVersionResource{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: "k8srequiredlabels"},
			resourceName: "k8srequiredlabels",
			expected:     true,
		},
		{
			name:         "known policy group kyverno.io",
			gvr:          schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"},
			resourceName: "clusterpolicies",
			expected:     true,
		},
		{
			name:         "known policy group security.istio.io",
			gvr:          schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"},
			resourceName: "authorizationpolicies",
			expected:     true,
		},
		{
			name:         "known policy group admissionregistration.k8s.io",
			gvr:          schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
			resourceName: "validatingwebhookconfigurations",
			expected:     true,
		},
		{
			name:         "registered adapter GVR",
			gvr:          schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			resourceName: "networkpolicies",
			expected:     true,
		},
		{
			name:         "native resourcequotas",
			gvr:          schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
			resourceName: "resourcequotas",
			expected:     true,
		},
		{
			name:         "native limitranges",
			gvr:          schema.GroupVersionResource{Group: "", Version: "v1", Resource: "limitranges"},
			resourceName: "limitranges",
			expected:     true,
		},
		{
			name:         "heuristic match - policy in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "securitypolicies"},
			resourceName: "securitypolicies",
			expected:     true,
		},
		{
			name:         "heuristic match - constraint in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "deploymentconstraints"},
			resourceName: "deploymentconstraints",
			expected:     true,
		},
		{
			name:         "heuristic match - quota in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "teamquotas"},
			resourceName: "teamquotas",
			expected:     true,
		},
		{
			name:         "heuristic match - limit in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "ratelimits"},
			resourceName: "ratelimits",
			expected:     true,
		},
		{
			name:         "heuristic match - rule in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "alertrules"},
			resourceName: "alertrules",
			expected:     true,
		},
		{
			name:         "heuristic match - authorization in name",
			gvr:          schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "serviceauthorization"},
			resourceName: "serviceauthorization",
			expected:     true,
		},
		{
			name:         "not constraint-like",
			gvr:          schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			resourceName: "deployments",
			expected:     false,
		},
		{
			name:         "not constraint-like pods",
			gvr:          schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			resourceName: "pods",
			expected:     false,
		},
		{
			name:         "not constraint-like services",
			gvr:          schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
			resourceName: "services",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.isConstraintLike(tt.gvr, tt.resourceName)
			assert.Equal(t, tt.expected, result, "isConstraintLike(%s, %s)", tt.gvr.String(), tt.resourceName)
		})
	}
}

func TestParseObject_WithRegisteredAdapter(t *testing.T) {
	engine, _ := setupTestEngine(t)

	ctx := context.Background()
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "deny-all",
				"namespace": "default",
				"uid":       "test-uid-1",
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"policyTypes": []interface{}{"Ingress"},
			},
		},
	}

	constraints, err := engine.parseObject(ctx, gvr, obj)
	require.NoError(t, err)
	require.NotEmpty(t, constraints)
	assert.Equal(t, "deny-all", constraints[0].Name)
}

func TestParseObject_FallbackToGeneric(t *testing.T) {
	engine, _ := setupTestEngine(t)

	ctx := context.Background()
	gvr := schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "customconstraints"}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "custom.io/v1",
			"kind":       "CustomConstraint",
			"metadata": map[string]interface{}{
				"name":      "my-custom",
				"namespace": "production",
				"uid":       "test-uid-2",
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "web",
					},
				},
			},
		},
	}

	constraints, err := engine.parseObject(ctx, gvr, obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)
	assert.Equal(t, "my-custom", constraints[0].Name)
	assert.Equal(t, "production", constraints[0].Namespace)
}

func TestHandleAdd(t *testing.T) {
	engine, idx := setupTestEngine(t)
	ctx := context.Background()

	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	engine.watchedGVRs[gvr] = true

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "test-np",
				"namespace": "default",
				"uid":       "add-uid-1",
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"policyTypes": []interface{}{"Ingress"},
			},
		},
	}

	engine.handleAdd(ctx, gvr, obj)

	// Verify constraint was added to indexer
	constraints := idx.ByNamespace("default")
	require.NotEmpty(t, constraints)
	assert.Equal(t, "test-np", constraints[0].Name)
}

func TestHandleAdd_NonUnstructured(t *testing.T) {
	engine, idx := setupTestEngine(t)
	ctx := context.Background()

	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "things"}

	// Pass a non-unstructured object — should be handled gracefully
	engine.handleAdd(ctx, gvr, "not-an-unstructured")

	// No constraints should be added
	assert.Empty(t, idx.All())
}

func TestHandleUpdate(t *testing.T) {
	engine, idx := setupTestEngine(t)
	ctx := context.Background()

	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	engine.watchedGVRs[gvr] = true

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "update-np",
				"namespace": "default",
				"uid":       "update-uid-1",
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"policyTypes": []interface{}{"Egress"},
			},
		},
	}

	// handleUpdate calls handleAdd internally
	engine.handleUpdate(ctx, gvr, obj)

	constraints := idx.ByNamespace("default")
	require.NotEmpty(t, constraints)

	found := false
	for _, c := range constraints {
		if c.Name == "update-np" {
			found = true
		}
	}
	assert.True(t, found, "updated constraint should be in indexer")
}

func TestHandleDelete(t *testing.T) {
	engine, idx := setupTestEngine(t)

	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}

	uid := types.UID("delete-uid-1")

	// Manually add a constraint to the indexer
	idx.Upsert(internaltypes.Constraint{
		UID:       uid,
		Name:      "to-delete",
		Namespace: "default",
	})
	require.NotEmpty(t, idx.All())

	// Delete with unstructured object
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      "to-delete",
				"namespace": "default",
				"uid":       string(uid),
			},
		},
	}

	engine.handleDelete(context.Background(), gvr, obj)

	// Constraint should be removed
	assert.Empty(t, idx.All())
}

func TestHandleDelete_Tombstone(t *testing.T) {
	engine, idx := setupTestEngine(t)

	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}

	uid := types.UID("tombstone-uid")

	// Manually add a constraint to the indexer
	idx.Upsert(internaltypes.Constraint{
		UID:       uid,
		Name:      "tombstone-item",
		Namespace: "default",
	})
	require.NotEmpty(t, idx.All())

	// Delete with tombstone wrapping an unstructured object
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      "tombstone-item",
				"namespace": "default",
				"uid":       string(uid),
			},
		},
	}
	tombstone := cache.DeletedFinalStateUnknown{
		Key: "default/tombstone-item",
		Obj: obj,
	}

	engine.handleDelete(context.Background(), gvr, tombstone)

	// Constraint should be removed
	assert.Empty(t, idx.All())
}

func TestHandleDelete_NonUnstructured(t *testing.T) {
	engine, _ := setupTestEngine(t)

	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "things"}

	// Pass a non-unstructured object — should not panic
	engine.handleDelete(context.Background(), gvr, "not-an-unstructured")
}

func TestHandleDelete_TombstoneNonUnstructured(t *testing.T) {
	engine, _ := setupTestEngine(t)

	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "things"}

	// Tombstone wrapping non-unstructured
	tombstone := cache.DeletedFinalStateUnknown{
		Key: "default/item",
		Obj: "not-an-unstructured",
	}

	// Should not panic
	engine.handleDelete(context.Background(), gvr, tombstone)
}

func TestScan(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()
	npAdapter := networkpolicy.New()
	err := registry.Register(npAdapter)
	require.NoError(t, err)

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "networkpolicies"},
				{Name: "networkpolicies/status"}, // sub-resource, should be skipped
			},
		},
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: "deployments"},
			},
		},
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "resourcequotas"},
				{Name: "pods"},
			},
		},
		{
			GroupVersion: "custom.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "securitypolicies"}, // matches heuristic
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}: "NetworkPolicyList",
		{Group: "", Version: "v1", Resource: "resourcequotas"}:                   "ResourceQuotaList",
		{Group: "custom.io", Version: "v1", Resource: "securitypolicies"}:        "SecurityPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(
		zap.NewNop(),
		mockDisc,
		dynClient,
		registry,
		idx,
		5*time.Minute,
	)

	ctx := context.Background()
	err = engine.scan(ctx)
	require.NoError(t, err)

	// Should have discovered: networkpolicies, resourcequotas, securitypolicies
	// Should NOT have discovered: deployments, pods, networkpolicies/status
	gvrs := engine.WatchedGVRs()
	assert.GreaterOrEqual(t, len(gvrs), 3, "should discover at least 3 constraint-like resources")

	gvrStrings := make(map[string]bool)
	for _, gvr := range gvrs {
		gvrStrings[gvr.String()] = true
	}
	assert.True(t, gvrStrings["networking.k8s.io/v1, Resource=networkpolicies"], "should watch networkpolicies")
	assert.True(t, gvrStrings["/v1, Resource=resourcequotas"], "should watch resourcequotas")
	assert.True(t, gvrStrings["custom.io/v1, Resource=securitypolicies"], "should watch securitypolicies (heuristic)")
	assert.False(t, gvrStrings["apps/v1, Resource=deployments"], "should NOT watch deployments")

	// Clean up informers
	engine.Stop()
}

func TestScan_RescanDoesNotDuplicate(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "cilium.io/v2",
			APIResources: []metav1.APIResource{
				{Name: "ciliumnetworkpolicies"},
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}: "CiliumNetworkPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(
		zap.NewNop(),
		mockDisc,
		dynClient,
		registry,
		idx,
		5*time.Minute,
	)

	ctx := context.Background()

	// First scan
	err := engine.scan(ctx)
	require.NoError(t, err)
	assert.Len(t, engine.WatchedGVRs(), 1)

	// Second scan with same resources — should not add duplicates
	err = engine.scan(ctx)
	require.NoError(t, err)
	assert.Len(t, engine.WatchedGVRs(), 1)

	engine.Stop()
}

func TestScan_PartialError(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "networkpolicies"},
			},
		},
	})
	// Set partial error (scan should continue with partial results)
	mockDisc.scanErr = assert.AnError

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}: "NetworkPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 5*time.Minute)

	ctx := context.Background()
	err := engine.scan(ctx)
	// scan should not return error even with partial discovery errors
	require.NoError(t, err)

	// Should still have found networkpolicies from the partial results
	assert.Len(t, engine.WatchedGVRs(), 1)

	engine.Stop()
}

func TestStart_Success(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "networkpolicies"},
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}: "NetworkPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		engine.Stop()
	}()

	err := engine.Start(ctx)
	require.NoError(t, err)

	// Verify initial scan was performed
	gvrs := engine.WatchedGVRs()
	assert.GreaterOrEqual(t, len(gvrs), 1, "initial scan should discover resources")
}

func TestStart_ScanError(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery(nil)
	mockDisc.scanErr = assert.AnError
	// With nil resources AND an error, scan will still return nil
	// since the error is treated as partial. Let's make discovery return completely empty.

	gvrToListKind := map[schema.GroupVersionResource]string{}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		engine.Stop()
	}()

	// Start should succeed even with partial error
	err := engine.Start(ctx)
	require.NoError(t, err)
}

func TestStart_PeriodicRescan(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "networking.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "networkpolicies"},
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}: "NetworkPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Use very short rescan interval
	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	err := engine.Start(ctx)
	require.NoError(t, err)

	// Wait for at least one periodic rescan
	time.Sleep(150 * time.Millisecond)

	// Cancel and clean up
	cancel()
	engine.Stop()

	// Verify the scan was performed (GVRs should be watched)
	gvrs := engine.WatchedGVRs()
	assert.GreaterOrEqual(t, len(gvrs), 1)
}

func TestStart_PeriodicRescan_Error(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	// First call succeeds, set error after
	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "resourcequotas"},
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "", Version: "v1", Resource: "resourcequotas"}: "ResourceQuotaList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	err := engine.Start(ctx)
	require.NoError(t, err)

	// Set error for rescan
	mockDisc.setScanErr(assert.AnError)

	// Wait for periodic rescan to fire (should log error but not crash)
	time.Sleep(150 * time.Millisecond)

	cancel()
	engine.Stop()
}

func TestScan_InvalidGroupVersion(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	mockDisc := newMockDiscovery([]*metav1.APIResourceList{
		{
			GroupVersion: "invalid///gv",
			APIResources: []metav1.APIResource{
				{Name: "something"},
			},
		},
		{
			GroupVersion: "valid.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "securitypolicies"}, // matches heuristic
			},
		},
	})

	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "valid.io", Version: "v1", Resource: "securitypolicies"}: "SecurityPolicyList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), mockDisc, dynClient, registry, idx, 5*time.Minute)

	ctx := context.Background()
	err := engine.scan(ctx)
	require.NoError(t, err)

	// Should still find valid resources despite invalid GV
	gvrs := engine.WatchedGVRs()
	assert.GreaterOrEqual(t, len(gvrs), 1)

	engine.Stop()
}

func TestParseObject_GroupBasedMatching(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	// Register gatekeeper adapter which handles constraints.gatekeeper.sh group
	// But since we can't easily import gatekeeper adapter, let's test with generic fallback
	engine := NewEngine(
		zap.NewNop(),
		nil,
		nil,
		registry,
		idx,
		5*time.Minute,
	)

	ctx := context.Background()
	// An unknown GVR with no adapter registered - should fall back to generic
	gvr := schema.GroupVersionResource{Group: "unknown.io", Version: "v1", Resource: "thingamajigs"}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "unknown.io/v1",
			"kind":       "Thingamajig",
			"metadata": map[string]interface{}{
				"name":      "test-thing",
				"namespace": "staging",
				"uid":       "generic-uid",
			},
		},
	}

	constraints, err := engine.parseObject(ctx, gvr, obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)
	assert.Equal(t, "test-thing", constraints[0].Name)
	assert.Equal(t, internaltypes.ConstraintTypeUnknown, constraints[0].ConstraintType)
}

// --- Phase 6: ConstraintProfile and annotation tests ---

func TestRegisterProfile_StartsInformer(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "custom.io", Version: "v1", Resource: "restrictions"}: "RestrictionList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), nil, dynClient, registry, idx, 5*time.Minute)

	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR:     v1alpha1.GVRReference{Group: "custom.io", Version: "v1", Resource: "restrictions"},
			Adapter: "generic",
			Enabled: true,
		},
	}

	err := engine.RegisterProfile(profile)
	require.NoError(t, err)

	// GVR should now be watched
	gvrs := engine.WatchedGVRs()
	require.Len(t, gvrs, 1)
	assert.Equal(t, "custom.io", gvrs[0].Group)
	assert.Equal(t, "restrictions", gvrs[0].Resource)

	engine.Stop()
}

func TestUnregisterProfile_CleansUpConstraints(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "custom.io", Version: "v1", Resource: "restrictions"}: "RestrictionList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	engine := NewEngine(zap.NewNop(), nil, dynClient, registry, idx, 5*time.Minute)

	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR:     v1alpha1.GVRReference{Group: "custom.io", Version: "v1", Resource: "restrictions"},
			Adapter: "generic",
			Enabled: true,
		},
	}

	require.NoError(t, engine.RegisterProfile(profile))

	// Simulate some constraints being indexed for this GVR
	gvr := schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "restrictions"}
	idx.Upsert(internaltypes.Constraint{
		UID:    "uid-1",
		Source: gvr,
		Name:   "constraint-1",
	})
	idx.Upsert(internaltypes.Constraint{
		UID:    "uid-2",
		Source: gvr,
		Name:   "constraint-2",
	})
	assert.Equal(t, 2, idx.Count())

	engine.UnregisterProfile("cleanup-profile")

	// Constraints should be cleaned up
	assert.Equal(t, 0, idx.Count())
	// GVR should no longer be watched
	assert.Empty(t, engine.WatchedGVRs())

	engine.Stop()
}

func TestRegisterProfile_DisabledSuppressesGVR(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	engine := NewEngine(zap.NewNop(), nil, nil, registry, idx, 5*time.Minute)

	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR:     v1alpha1.GVRReference{Group: "custom.io", Version: "v1", Resource: "stuff"},
			Adapter: "generic",
			Enabled: false,
		},
	}

	err := engine.RegisterProfile(profile)
	require.NoError(t, err)

	// Should NOT start an informer for disabled profile
	assert.Empty(t, engine.WatchedGVRs())

	engine.Stop()
}

func TestIsConstraintLike_WithProfile(t *testing.T) {
	engine, _ := setupTestEngine(t)

	customGVR := schema.GroupVersionResource{Group: "custom.corp.io", Version: "v1", Resource: "widgetpolicies"}

	// Before profile: not recognized (custom.corp.io is not a known policy group, "widgetpolicies" matches "policies" heuristic though)
	// Let's use something that does NOT match heuristics
	oddGVR := schema.GroupVersionResource{Group: "odd.corp.io", Version: "v1", Resource: "foobar"}
	assert.False(t, engine.isConstraintLike(oddGVR, "foobar"))

	// Register profile
	engine.mu.Lock()
	engine.profiles["test"] = &profileState{
		gvr:     oddGVR,
		enabled: true,
	}
	engine.mu.Unlock()

	assert.True(t, engine.isConstraintLike(oddGVR, "foobar"))

	// Disabled profile should not match
	engine.mu.Lock()
	engine.profiles["test"].enabled = false
	engine.mu.Unlock()

	assert.False(t, engine.isConstraintLike(oddGVR, "foobar"))

	_ = customGVR // avoid unused
}

func TestIsConstraintLike_WithAnnotatedCRD(t *testing.T) {
	engine, _ := setupTestEngine(t)

	annotatedGVR := schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "widgets"}
	assert.False(t, engine.isConstraintLike(annotatedGVR, "widgets"))

	// Simulate annotated CRD cache
	engine.mu.Lock()
	engine.annotatedCRDs[annotatedGVR] = true
	engine.mu.Unlock()

	assert.True(t, engine.isConstraintLike(annotatedGVR, "widgets"))
}

func TestSetAdditionalGroups(t *testing.T) {
	engine, _ := setupTestEngine(t)

	customGVR := schema.GroupVersionResource{Group: "custom.corp.io", Version: "v1", Resource: "widgets"}
	assert.False(t, engine.isConstraintLike(customGVR, "widgets"))

	engine.SetAdditionalGroups([]string{"custom.corp.io"})
	assert.True(t, engine.isConstraintLike(customGVR, "widgets"))
}

func TestSetAdditionalHints(t *testing.T) {
	engine, _ := setupTestEngine(t)

	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "guardrails"}
	assert.False(t, engine.isConstraintLike(gvr, "guardrails"))

	engine.SetAdditionalHints([]string{"guardrail"})
	assert.True(t, engine.isConstraintLike(gvr, "guardrails"))
}

func TestParseObject_WithProfileConfig(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	engine := NewEngine(zap.NewNop(), nil, nil, registry, idx, 5*time.Minute)

	gvr := schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "deployrestrictions"}

	// Register a profile with field paths and severity override
	engine.mu.Lock()
	engine.profiles["deploy-profile"] = &profileState{
		gvr:     gvr,
		adapter: "generic",
		enabled: true,
		fieldPaths: &v1alpha1.FieldPaths{
			EffectPath: "spec.action",
		},
		severity: "Critical",
	}
	engine.mu.Unlock()

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "custom.io/v1",
			"kind":       "DeployRestriction",
			"metadata": map[string]interface{}{
				"name":      "test-restrict",
				"namespace": "prod",
				"uid":       "uid-profile-test",
			},
			"spec": map[string]interface{}{
				"action": "deny",
			},
		},
	}

	constraints, err := engine.parseObject(context.Background(), gvr, obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, "deny", c.Effect)
	assert.Equal(t, internaltypes.SeverityCritical, c.Severity)
}

func TestRefreshAnnotatedCRDs(t *testing.T) {
	idx := indexer.New(nil)
	registry := adapters.NewRegistry()

	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	gvrToListKind := map[schema.GroupVersionResource]string{
		crdGVR: "CustomResourceDefinitionList",
	}
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind,
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apiextensions.k8s.io/v1",
				"kind":       "CustomResourceDefinition",
				"metadata": map[string]interface{}{
					"name": "widgets.custom.io",
					"annotations": map[string]interface{}{
						"potoo.io/is-policy": "true",
					},
				},
				"spec": map[string]interface{}{
					"group": "custom.io",
					"names": map[string]interface{}{
						"plural": "widgets",
					},
					"versions": []interface{}{
						map[string]interface{}{
							"name":    "v1",
							"served":  true,
							"storage": true,
						},
					},
				},
			},
		},
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apiextensions.k8s.io/v1",
				"kind":       "CustomResourceDefinition",
				"metadata": map[string]interface{}{
					"name": "things.other.io",
					// No is-policy annotation
				},
				"spec": map[string]interface{}{
					"group": "other.io",
					"names": map[string]interface{}{
						"plural": "things",
					},
					"versions": []interface{}{
						map[string]interface{}{
							"name":    "v1",
							"served":  true,
							"storage": true,
						},
					},
				},
			},
		},
	)

	engine := NewEngine(zap.NewNop(), nil, dynClient, registry, idx, 5*time.Minute)
	engine.refreshAnnotatedCRDs(context.Background())

	widgetGVR := schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "widgets"}
	thingGVR := schema.GroupVersionResource{Group: "other.io", Version: "v1", Resource: "things"}

	engine.mu.RLock()
	assert.True(t, engine.annotatedCRDs[widgetGVR], "annotated CRD should be detected")
	assert.False(t, engine.annotatedCRDs[thingGVR], "non-annotated CRD should not be detected")
	engine.mu.RUnlock()

	// isConstraintLike should recognize the annotated GVR
	assert.True(t, engine.isConstraintLike(widgetGVR, "widgets"))
}

func TestDeleteBySource(t *testing.T) {
	idx := indexer.New(nil)
	gvr1 := schema.GroupVersionResource{Group: "a.io", Version: "v1", Resource: "foos"}
	gvr2 := schema.GroupVersionResource{Group: "b.io", Version: "v1", Resource: "bars"}

	idx.Upsert(internaltypes.Constraint{UID: "1", Source: gvr1, Name: "foo-1"})
	idx.Upsert(internaltypes.Constraint{UID: "2", Source: gvr1, Name: "foo-2"})
	idx.Upsert(internaltypes.Constraint{UID: "3", Source: gvr2, Name: "bar-1"})

	assert.Equal(t, 3, idx.Count())

	n := idx.DeleteBySource(gvr1)
	assert.Equal(t, 2, n)
	assert.Equal(t, 1, idx.Count())

	remaining := idx.All()
	require.Len(t, remaining, 1)
	assert.Equal(t, "bar-1", remaining[0].Name)
}
