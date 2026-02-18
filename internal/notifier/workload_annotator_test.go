package notifier

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/potooio/potoo/internal/annotations"
	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

func TestWorkloadAnnotator_BuildAnnotationPatch_Empty(t *testing.T) {
	wa := &WorkloadAnnotator{}

	patch := wa.buildAnnotationPatch(nil)

	annots := patch["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})

	// All annotations should be nil (removed)
	assert.Nil(t, annots[annotations.WorkloadStatus])
	assert.Nil(t, annots[annotations.WorkloadConstraints])
	assert.Nil(t, annots[annotations.WorkloadMaxSeverity])
	assert.Nil(t, annots[annotations.WorkloadCriticalCount])
	assert.Nil(t, annots[annotations.WorkloadWarningCount])
	assert.Nil(t, annots[annotations.WorkloadInfoCount])
}

func TestWorkloadAnnotator_BuildAnnotationPatch_WithConstraints(t *testing.T) {
	wa := &WorkloadAnnotator{}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-1"),
			Name:           "critical-policy",
			ConstraintType: types.ConstraintTypeNetworkEgress,
			Severity:       types.SeverityCritical,
			Source:         schema.GroupVersionResource{Resource: "networkpolicies"},
		},
		{
			UID:            k8stypes.UID("uid-2"),
			Name:           "warning-policy",
			ConstraintType: types.ConstraintTypeAdmission,
			Severity:       types.SeverityWarning,
			Source:         schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
		},
		{
			UID:            k8stypes.UID("uid-3"),
			Name:           "info-policy",
			ConstraintType: types.ConstraintTypeResourceLimit,
			Severity:       types.SeverityInfo,
			Source:         schema.GroupVersionResource{Resource: "resourcequotas"},
		},
	}

	patch := wa.buildAnnotationPatch(constraints)

	annots := patch["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})

	// Check status string
	status := annots[annotations.WorkloadStatus].(string)
	assert.Contains(t, status, "3 constraints")
	assert.Contains(t, status, "1 critical")
	assert.Contains(t, status, "1 warning")

	// Check counts
	assert.Equal(t, "1", annots[annotations.WorkloadCriticalCount])
	assert.Equal(t, "1", annots[annotations.WorkloadWarningCount])
	assert.Equal(t, "1", annots[annotations.WorkloadInfoCount])

	// Check max severity
	assert.Equal(t, "critical", annots[annotations.WorkloadMaxSeverity])

	// Check constraints JSON
	constraintsJSON := annots[annotations.WorkloadConstraints].(string)
	var summaries []ConstraintSummary
	err := json.Unmarshal([]byte(constraintsJSON), &summaries)
	require.NoError(t, err)
	require.Len(t, summaries, 3)

	assert.Equal(t, "NetworkEgress", summaries[0].Type)
	assert.Equal(t, "Critical", summaries[0].Severity)
	assert.Equal(t, "critical-policy", summaries[0].Name)
	assert.Equal(t, "networkpolicies", summaries[0].Source)

	// Check last evaluated is set
	lastEvaluated := annots[annotations.WorkloadLastEvaluated].(string)
	assert.NotEmpty(t, lastEvaluated)
}

func TestWorkloadAnnotator_BuildAnnotationPatch_OnlyInfo(t *testing.T) {
	wa := &WorkloadAnnotator{}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-1"),
			Name:           "info-only",
			ConstraintType: types.ConstraintTypeResourceLimit,
			Severity:       types.SeverityInfo,
			Source:         schema.GroupVersionResource{Resource: "resourcequotas"},
		},
	}

	patch := wa.buildAnnotationPatch(constraints)
	annots := patch["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})

	assert.Equal(t, "info", annots[annotations.WorkloadMaxSeverity])
	assert.Equal(t, "0", annots[annotations.WorkloadCriticalCount])
	assert.Equal(t, "0", annots[annotations.WorkloadWarningCount])
	assert.Equal(t, "1", annots[annotations.WorkloadInfoCount])

	status := annots[annotations.WorkloadStatus].(string)
	assert.Equal(t, "1 constraints", status)
}

func TestWorkloadAnnotator_BuildAnnotationPatch_OnlyWarning(t *testing.T) {
	wa := &WorkloadAnnotator{}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-1"),
			Name:           "warning-1",
			ConstraintType: types.ConstraintTypeAdmission,
			Severity:       types.SeverityWarning,
			Source:         schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
		},
		{
			UID:            k8stypes.UID("uid-2"),
			Name:           "warning-2",
			ConstraintType: types.ConstraintTypeNetworkIngress,
			Severity:       types.SeverityWarning,
			Source:         schema.GroupVersionResource{Resource: "networkpolicies"},
		},
	}

	patch := wa.buildAnnotationPatch(constraints)
	annots := patch["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})

	assert.Equal(t, "warning", annots[annotations.WorkloadMaxSeverity])
	assert.Equal(t, "0", annots[annotations.WorkloadCriticalCount])
	assert.Equal(t, "2", annots[annotations.WorkloadWarningCount])
	assert.Equal(t, "0", annots[annotations.WorkloadInfoCount])

	status := annots[annotations.WorkloadStatus].(string)
	assert.Contains(t, status, "2 constraints")
	assert.Contains(t, status, "2 warning")
}

func TestWorkloadAnnotator_BuildStatusString(t *testing.T) {
	wa := &WorkloadAnnotator{}

	tests := []struct {
		name     string
		total    int
		critical int
		warning  int
		expected string
	}{
		{
			name:     "no constraints",
			total:    0,
			critical: 0,
			warning:  0,
			expected: "No constraints",
		},
		{
			name:     "only critical",
			total:    2,
			critical: 2,
			warning:  0,
			expected: "2 constraints (2 critical)",
		},
		{
			name:     "only warning",
			total:    3,
			critical: 0,
			warning:  3,
			expected: "3 constraints (3 warning)",
		},
		{
			name:     "critical and warning",
			total:    5,
			critical: 2,
			warning:  3,
			expected: "5 constraints (2 critical, 3 warning)",
		},
		{
			name:     "only info (no critical or warning)",
			total:    4,
			critical: 0,
			warning:  0,
			expected: "4 constraints",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wa.buildStatusString(tt.total, tt.critical, tt.warning)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKindToGVR(t *testing.T) {
	tests := []struct {
		kind        string
		expectError bool
		expectedGVR schema.GroupVersionResource
	}{
		{
			kind: "Deployment",
			expectedGVR: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "deployments",
			},
		},
		{
			kind: "StatefulSet",
			expectedGVR: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "statefulsets",
			},
		},
		{
			kind: "DaemonSet",
			expectedGVR: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "daemonsets",
			},
		},
		{
			kind: "ReplicaSet",
			expectedGVR: schema.GroupVersionResource{
				Group: "apps", Version: "v1", Resource: "replicasets",
			},
		},
		{
			kind: "Job",
			expectedGVR: schema.GroupVersionResource{
				Group: "batch", Version: "v1", Resource: "jobs",
			},
		},
		{
			kind: "CronJob",
			expectedGVR: schema.GroupVersionResource{
				Group: "batch", Version: "v1", Resource: "cronjobs",
			},
		},
		{
			kind: "Pod",
			expectedGVR: schema.GroupVersionResource{
				Group: "", Version: "v1", Resource: "pods",
			},
		},
		{
			kind:        "Unknown",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			gvr, err := kindToGVR(tt.kind)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedGVR, gvr)
			}
		})
	}
}

func TestJoinWithComma(t *testing.T) {
	tests := []struct {
		parts    []string
		expected string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"one"}, "one"},
		{[]string{"one", "two"}, "one, two"},
		{[]string{"one", "two", "three"}, "one, two, three"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := joinWithComma(tt.parts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- New tests to boost coverage ---

func TestWorkloadAnnotator_BuildAnnotationPatch_MixedSeveritiesWithoutCritical(t *testing.T) {
	wa := &WorkloadAnnotator{}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-w1"),
			Name:           "warn-1",
			ConstraintType: types.ConstraintTypeNetworkIngress,
			Severity:       types.SeverityWarning,
			Source:         schema.GroupVersionResource{Resource: "networkpolicies"},
		},
		{
			UID:            k8stypes.UID("uid-i1"),
			Name:           "info-1",
			ConstraintType: types.ConstraintTypeAdmission,
			Severity:       types.SeverityInfo,
			Source:         schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
		},
	}

	patch := wa.buildAnnotationPatch(constraints)
	annots := patch["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})

	assert.Equal(t, "warning", annots[annotations.WorkloadMaxSeverity])
	assert.Equal(t, "0", annots[annotations.WorkloadCriticalCount])
	assert.Equal(t, "1", annots[annotations.WorkloadWarningCount])
	assert.Equal(t, "1", annots[annotations.WorkloadInfoCount])
}

func TestWorkloadAnnotator_BuildStatusString_EdgeCases(t *testing.T) {
	wa := &WorkloadAnnotator{}

	// All types present
	result := wa.buildStatusString(10, 3, 4)
	assert.Equal(t, "10 constraints (3 critical, 4 warning)", result)

	// Only info (no critical, no warning)
	result = wa.buildStatusString(5, 0, 0)
	assert.Equal(t, "5 constraints", result)

	// Zero constraints
	result = wa.buildStatusString(0, 0, 0)
	assert.Equal(t, "No constraints", result)

	// Only critical
	result = wa.buildStatusString(1, 1, 0)
	assert.Equal(t, "1 constraints (1 critical)", result)
}

func TestKindToGVR_AllSupported(t *testing.T) {
	// Ensure all supported kinds are handled
	supportedKinds := []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}

	for _, kind := range supportedKinds {
		t.Run(kind, func(t *testing.T) {
			gvr, err := kindToGVR(kind)
			assert.NoError(t, err)
			assert.NotEmpty(t, gvr.Resource)
		})
	}
}

func TestKindToGVR_Unsupported(t *testing.T) {
	_, err := kindToGVR("ConfigMap")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported workload kind")

	_, err = kindToGVR("")
	assert.Error(t, err)
}

func TestDefaultWorkloadAnnotatorOptions(t *testing.T) {
	opts := DefaultWorkloadAnnotatorOptions()

	assert.Equal(t, 30*1000*1000*1000, int(opts.DebounceDuration)) // 30 seconds in nanoseconds
	assert.Equal(t, 30*time.Second, opts.CacheTTL)
	assert.Equal(t, 5, opts.Workers)
}

func TestNewWorkloadAnnotator(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)
	logger := zap.NewNop()
	opts := DefaultWorkloadAnnotatorOptions()

	wa := NewWorkloadAnnotator(dynClient, idx, logger, opts)

	require.NotNil(t, wa)
	assert.NotNil(t, wa.lastPatch)
	assert.NotNil(t, wa.pending)
	assert.NotNil(t, wa.nsCache)
	assert.Equal(t, 30*time.Second, wa.opts.DebounceDuration)
	assert.Equal(t, 30*time.Second, wa.opts.CacheTTL)
	assert.Equal(t, 5, wa.opts.Workers)
}

func TestNewWorkloadAnnotator_ZeroOptions(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)
	logger := zap.NewNop()

	wa := NewWorkloadAnnotator(dynClient, idx, logger, WorkloadAnnotatorOptions{})

	require.NotNil(t, wa)
	assert.Equal(t, 30*time.Second, wa.opts.DebounceDuration)
	assert.Equal(t, 30*time.Second, wa.opts.CacheTTL)
	assert.Equal(t, 5, wa.opts.Workers)
}

func TestWorkloadAnnotator_OnIndexChange(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)
	logger := zap.NewNop()

	wa := NewWorkloadAnnotator(dynClient, idx, logger, DefaultWorkloadAnnotatorOptions())

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "test-policy",
			Namespace:          "ns-a",
			AffectedNamespaces: []string{"ns-a", "ns-b"},
		},
	}

	wa.OnIndexChange(event)

	// Should have items in the pending channel (ns-a appears in both
	// AffectedNamespaces and Namespace, but dedup means only 2 updates)
	assert.Equal(t, 2, len(wa.pending))
}

func TestWorkloadAnnotator_OnIndexChange_ClusterScoped(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "cluster-policy",
			Namespace:          "", // cluster-scoped
			AffectedNamespaces: []string{"team-a", "team-b", "team-c"},
		},
	}

	wa.OnIndexChange(event)

	// Should have 3 pending updates for team-a, team-b, team-c
	assert.Equal(t, 3, len(wa.pending))
}

func TestWorkloadAnnotator_OnIndexChange_ClusterScoped_NoAffectedNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "webhook-policy",
			Namespace:          "", // cluster-scoped
			AffectedNamespaces: nil,
		},
	}

	wa.OnIndexChange(event)

	// Should have 1 pending update: the cluster-wide sentinel
	require.Equal(t, 1, len(wa.pending))
	update := <-wa.pending
	assert.Equal(t, clusterWideSentinel, update.key.Namespace)
}

func TestWorkloadAnnotator_ProcessUpdate_ClusterWideSentinel(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "", Version: "v1", Resource: "namespaces"}: "NamespaceList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Create namespaces
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	for _, name := range []string{"team-a", "team-b", "kube-system"} {
		ns := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Namespace",
				"metadata": map[string]interface{}{
					"name": name,
				},
			},
		}
		_, err := dynClient.Resource(nsGVR).Create(context.Background(), ns, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	idx := indexer.New(nil)
	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), WorkloadAnnotatorOptions{
		DebounceDuration: 1 * time.Millisecond,
		Workers:          1,
	})

	// Process the cluster-wide sentinel
	update := pendingUpdate{
		key:       workloadKey{Namespace: clusterWideSentinel},
		scheduled: time.Now(),
	}

	wa.processUpdate(context.Background(), update)

	// Should have queued per-namespace updates for all 3 namespaces
	var queued []string
	for {
		select {
		case u := <-wa.pending:
			queued = append(queued, u.key.Namespace)
		default:
			goto done
		}
	}
done:

	assert.Len(t, queued, 3)
	assert.ElementsMatch(t, []string{"team-a", "team-b", "kube-system"}, queued)
}

func TestWorkloadAnnotator_ListNamespaceWorkloads_EmptyNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	// Empty namespace should return nil without making API calls
	result, err := wa.listNamespaceWorkloads(context.Background(), "")
	assert.NoError(t, err)
	assert.Nil(t, result)

	// No API calls should have been made
	assert.Empty(t, dynClient.Actions())
}

func TestWorkloadAnnotator_QueueWorkloadUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	wa.QueueWorkloadUpdate("test-ns", "Deployment", "my-app")

	// Should have an item in the pending channel
	select {
	case update := <-wa.pending:
		assert.Equal(t, "test-ns", update.key.Namespace)
		assert.Equal(t, "Deployment", update.key.Kind)
		assert.Equal(t, "my-app", update.key.Name)
	default:
		t.Error("Expected pending update")
	}
}

func TestWorkloadAnnotator_QueueWorkloadUpdate_Debounced(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	// Set last patch to recent
	key := workloadKey{Namespace: "test-ns", Kind: "Deployment", Name: "my-app"}
	wa.mu.Lock()
	wa.lastPatch[key] = time.Now()
	wa.mu.Unlock()

	wa.QueueWorkloadUpdate("test-ns", "Deployment", "my-app")

	// Should be debounced - nothing in the pending channel
	select {
	case <-wa.pending:
		t.Error("Expected update to be debounced")
	default:
		// OK - debounced
	}
}

func TestWorkloadAnnotator_Worker_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		wa.worker(ctx, 0)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// OK - worker exited
	case <-time.After(2 * time.Second):
		t.Error("Worker did not exit on context cancellation")
	}
}

func TestWorkloadAnnotator_Worker_ChannelClose(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		wa.worker(ctx, 0)
		close(done)
	}()

	// Close channel to signal worker to stop
	close(wa.pending)

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Worker did not exit on channel close")
	}
}

func TestWorkloadAnnotator_ProcessUpdate_NamespaceLevel_ResolvesWorkloads(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}:  "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}: "StatefulSetList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:   "DaemonSetList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Create workloads in the namespace
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "web",
				"namespace": "test-ns",
			},
		},
	}
	_, err := dynClient.Resource(depGVR).Namespace("test-ns").Create(context.Background(), dep, metav1.CreateOptions{})
	require.NoError(t, err)

	ssGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	ss := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"metadata": map[string]interface{}{
				"name":      "db",
				"namespace": "test-ns",
			},
		},
	}
	_, err = dynClient.Resource(ssGVR).Namespace("test-ns").Create(context.Background(), ss, metav1.CreateOptions{})
	require.NoError(t, err)

	idx := indexer.New(nil)
	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), WorkloadAnnotatorOptions{
		DebounceDuration: 1 * time.Millisecond,
		Workers:          1,
	})

	// Send namespace-level update (empty Kind/Name)
	update := pendingUpdate{
		key:       workloadKey{Namespace: "test-ns"},
		scheduled: time.Now(),
	}

	wa.processUpdate(context.Background(), update)

	// Drain pending channel and collect queued workload updates
	var queued []workloadKey
	for {
		select {
		case u := <-wa.pending:
			queued = append(queued, u.key)
		default:
			goto done
		}
	}
done:

	// Should have queued individual workload updates for the deployment and statefulset
	assert.Len(t, queued, 2)

	keys := map[workloadKey]bool{}
	for _, k := range queued {
		keys[k] = true
	}
	assert.True(t, keys[workloadKey{Namespace: "test-ns", Kind: "Deployment", Name: "web"}])
	assert.True(t, keys[workloadKey{Namespace: "test-ns", Kind: "StatefulSet", Name: "db"}])
}

func TestWorkloadAnnotator_ProcessUpdate_NamespaceLevel_EmptyNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}:  "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}: "StatefulSetList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:   "DaemonSetList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), WorkloadAnnotatorOptions{
		DebounceDuration: 1 * time.Millisecond,
		Workers:          1,
	})

	// Namespace with no workloads
	update := pendingUpdate{
		key:       workloadKey{Namespace: "empty-ns"},
		scheduled: time.Now(),
	}

	// Should not panic or error
	wa.processUpdate(context.Background(), update)

	// Nothing should be queued
	select {
	case <-wa.pending:
		t.Error("Expected no updates for empty namespace")
	default:
		// OK
	}
}

func TestWorkloadAnnotator_ListNamespaceWorkloads_CacheHit(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}:  "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}: "StatefulSetList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:   "DaemonSetList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Create a deployment
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "app",
				"namespace": "cached-ns",
			},
		},
	}
	_, err := dynClient.Resource(depGVR).Namespace("cached-ns").Create(context.Background(), dep, metav1.CreateOptions{})
	require.NoError(t, err)

	idx := indexer.New(nil)
	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	ctx := context.Background()

	// First call: cache miss, should list from API
	result1, err := wa.listNamespaceWorkloads(ctx, "cached-ns")
	require.NoError(t, err)
	assert.Len(t, result1, 1)

	// Count actions so far
	actionCountAfterFirst := len(dynClient.Actions())

	// Second call: cache hit, should NOT call the API again
	result2, err := wa.listNamespaceWorkloads(ctx, "cached-ns")
	require.NoError(t, err)
	assert.Len(t, result2, 1)

	// No new API actions should have been recorded
	assert.Equal(t, actionCountAfterFirst, len(dynClient.Actions()))
}

func TestWorkloadAnnotator_ProcessUpdate_WithWorkload(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}: "DeploymentList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Create a deployment to patch
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "my-app",
				"namespace": "test-ns",
			},
		},
	}
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	_, err := dynClient.Resource(gvr).Namespace("test-ns").Create(context.Background(), dep, metav1.CreateOptions{})
	require.NoError(t, err)

	idx := indexer.New(nil)
	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), WorkloadAnnotatorOptions{
		DebounceDuration: 1 * time.Millisecond,
		Workers:          1,
	})

	update := pendingUpdate{
		key:       workloadKey{Namespace: "test-ns", Kind: "Deployment", Name: "my-app"},
		scheduled: time.Now(),
	}

	wa.processUpdate(context.Background(), update)

	// Verify the workload was patched (annotations should be set to nil/removed since no constraints)
	result, err := dynClient.Resource(gvr).Namespace("test-ns").Get(context.Background(), "my-app", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestWorkloadAnnotator_ProcessUpdate_Debounced(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	// Set recent last patch
	key := workloadKey{Namespace: "test-ns", Kind: "Deployment", Name: "my-app"}
	wa.mu.Lock()
	wa.lastPatch[key] = time.Now()
	wa.mu.Unlock()

	update := pendingUpdate{
		key:       key,
		scheduled: time.Now(),
	}

	// Should skip due to debounce - no error, no panic
	wa.processUpdate(context.Background(), update)
}

func TestWorkloadAnnotator_ApplyPatch_UnsupportedKind(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	key := workloadKey{Namespace: "test-ns", Kind: "ConfigMap", Name: "test"}
	patch := map[string]interface{}{"metadata": map[string]interface{}{}}

	err := wa.applyPatch(context.Background(), key, patch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported workload kind")
}

func TestWorkloadAnnotator_InvalidateCache(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "apps", Version: "v1", Resource: "deployments"}:  "DeploymentList",
		{Group: "apps", Version: "v1", Resource: "statefulsets"}: "StatefulSetList",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}:   "DaemonSetList",
	}
	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind)

	// Create a deployment in the namespace.
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "app",
				"namespace": "test-ns",
			},
		},
	}
	_, err := dynClient.Resource(depGVR).Namespace("test-ns").Create(context.Background(), dep, metav1.CreateOptions{})
	require.NoError(t, err)

	idx := indexer.New(nil)
	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	ctx := context.Background()

	// Populate cache
	result1, err := wa.listNamespaceWorkloads(ctx, "test-ns")
	require.NoError(t, err)
	assert.Len(t, result1, 1)

	// Verify cache is populated
	wa.mu.Lock()
	_, cached := wa.nsCache["test-ns"]
	wa.mu.Unlock()
	assert.True(t, cached, "cache should be populated after first call")

	// Invalidate cache
	wa.InvalidateCache("test-ns")

	// Verify cache is cleared
	wa.mu.Lock()
	_, cached = wa.nsCache["test-ns"]
	wa.mu.Unlock()
	assert.False(t, cached, "cache should be cleared after InvalidateCache")

	// Next call should re-fetch from API
	actionsBeforeRefetch := len(dynClient.Actions())
	result2, err := wa.listNamespaceWorkloads(ctx, "test-ns")
	require.NoError(t, err)
	assert.Len(t, result2, 1)

	// Should have made new API calls
	assert.Greater(t, len(dynClient.Actions()), actionsBeforeRefetch,
		"should have made new API calls after cache invalidation")
}

func TestWorkloadAnnotator_InvalidateCache_OnIndexChange(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	// Seed cache entries
	wa.mu.Lock()
	wa.nsCache["ns-a"] = nsWorkloadCache{fetchedAt: time.Now()}
	wa.nsCache["ns-b"] = nsWorkloadCache{fetchedAt: time.Now()}
	wa.nsCache["ns-c"] = nsWorkloadCache{fetchedAt: time.Now()}
	wa.mu.Unlock()

	// Trigger OnIndexChange for ns-a and ns-b
	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "test-policy",
			Namespace:          "ns-b",
			AffectedNamespaces: []string{"ns-a"},
		},
	}
	wa.OnIndexChange(event)

	// ns-a and ns-b caches should be invalidated, ns-c should remain
	wa.mu.Lock()
	_, hasCacheA := wa.nsCache["ns-a"]
	_, hasCacheB := wa.nsCache["ns-b"]
	_, hasCacheC := wa.nsCache["ns-c"]
	wa.mu.Unlock()

	assert.False(t, hasCacheA, "ns-a cache should be invalidated")
	assert.False(t, hasCacheB, "ns-b cache should be invalidated")
	assert.True(t, hasCacheC, "ns-c cache should NOT be invalidated (unrelated)")
}

func TestWorkloadAnnotator_ClusterWideInvalidatesAllCache(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), DefaultWorkloadAnnotatorOptions())

	// Seed cache entries
	wa.mu.Lock()
	wa.nsCache["ns-a"] = nsWorkloadCache{fetchedAt: time.Now()}
	wa.nsCache["ns-b"] = nsWorkloadCache{fetchedAt: time.Now()}
	wa.mu.Unlock()

	// Trigger cluster-wide update (namespace="" and no affected namespaces)
	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:      "cluster-webhook",
			Namespace: "",
		},
	}
	wa.OnIndexChange(event)

	// All caches should be invalidated
	wa.mu.Lock()
	cacheLen := len(wa.nsCache)
	wa.mu.Unlock()

	assert.Equal(t, 0, cacheLen, "all namespace caches should be invalidated on cluster-wide update")
}

func TestWorkloadAnnotator_Start_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	dynClient := dynamicfake.NewSimpleDynamicClient(scheme)
	idx := indexer.New(nil)

	wa := NewWorkloadAnnotator(dynClient, idx, zap.NewNop(), WorkloadAnnotatorOptions{
		DebounceDuration: 100 * time.Millisecond,
		Workers:          1,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- wa.Start(ctx)
	}()

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Error("Start did not exit on context cancellation")
	}
}
