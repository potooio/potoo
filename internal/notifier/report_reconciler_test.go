package notifier

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

func TestReportReconciler_BuildReportStatus(t *testing.T) {
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelSummary,
			DefaultContact:     "platform@example.com",
		},
	}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-1"),
			Name:           "critical-netpol",
			Namespace:      "team-alpha",
			ConstraintType: types.ConstraintTypeNetworkEgress,
			Severity:       types.SeverityCritical,
			Effect:         "deny",
			Summary:        "Denies all egress",
			Tags:           []string{"network", "egress"},
			Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		},
		{
			UID:            k8stypes.UID("uid-2"),
			Name:           "warning-quota",
			Namespace:      "team-alpha",
			ConstraintType: types.ConstraintTypeResourceLimit,
			Severity:       types.SeverityWarning,
			Effect:         "limit",
			Summary:        "CPU at 85%",
			Tags:           []string{"quota", "cpu"},
			Source:         schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"cpu": map[string]interface{}{
						"hard":    "4",
						"used":    "3.4",
						"percent": 85,
					},
				},
			},
		},
		{
			UID:            k8stypes.UID("uid-3"),
			Name:           "info-webhook",
			Namespace:      "",
			ConstraintType: types.ConstraintTypeAdmission,
			Severity:       types.SeverityInfo,
			Effect:         "intercept",
			Summary:        "Webhook validates pods",
			Tags:           []string{"admission"},
			Source:         schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
		},
	}

	status := rr.buildReportStatus(constraints, "team-alpha")

	// Check counts
	assert.Equal(t, 3, status.ConstraintCount)
	assert.Equal(t, 1, status.CriticalCount)
	assert.Equal(t, 1, status.WarningCount)
	assert.Equal(t, 1, status.InfoCount)

	// Check human-readable entries
	require.Len(t, status.Constraints, 3)
	// Should be sorted by severity: critical first
	assert.Equal(t, "Critical", status.Constraints[0].Severity)
	assert.Equal(t, "Warning", status.Constraints[1].Severity)
	assert.Equal(t, "Info", status.Constraints[2].Severity)

	// Check machine-readable section
	require.NotNil(t, status.MachineReadable)
	assert.Equal(t, "1", status.MachineReadable.SchemaVersion)
	assert.Equal(t, "summary", status.MachineReadable.DetailLevel)
	require.Len(t, status.MachineReadable.Constraints, 3)

	// Check tags are collected and sorted
	assert.Contains(t, status.MachineReadable.Tags, "network")
	assert.Contains(t, status.MachineReadable.Tags, "quota")
	assert.Contains(t, status.MachineReadable.Tags, "admission")

	// Check resource metrics are extracted
	quotaEntry := status.MachineReadable.Constraints[1] // Warning entry
	require.NotNil(t, quotaEntry.Metrics)
	cpuMetric, ok := quotaEntry.Metrics["cpu"]
	require.True(t, ok)
	assert.Equal(t, "4", cpuMetric.Hard)
	assert.Equal(t, "3.4", cpuMetric.Used)
	assert.Equal(t, float64(85), cpuMetric.PercentUsed)
	assert.Equal(t, "cores", cpuMetric.Unit)
}

func TestReportReconciler_BuildMachineEntry(t *testing.T) {
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelDetailed,
		},
	}

	c := types.Constraint{
		UID:            k8stypes.UID("test-uid"),
		Name:           "test-policy",
		Namespace:      "test-ns",
		ConstraintType: types.ConstraintTypeNetworkIngress,
		Severity:       types.SeverityWarning,
		Effect:         "restrict",
		Summary:        "Restricts ingress",
		Tags:           []string{"network", "ingress"},
		Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	entry := rr.buildMachineEntry(c, "test-ns")

	assert.Equal(t, "test-uid", entry.UID)
	assert.Equal(t, "test-policy", entry.Name)
	assert.Equal(t, "NetworkIngress", entry.ConstraintType)
	assert.Equal(t, "Warning", entry.Severity)
	assert.Equal(t, "restrict", entry.Effect)

	// Check source ref
	assert.Equal(t, "networking.k8s.io/v1", entry.SourceRef.APIVersion)
	assert.Equal(t, "NetworkPolicy", entry.SourceRef.Kind)
	assert.Equal(t, "test-policy", entry.SourceRef.Name)
	assert.Equal(t, "test-ns", entry.SourceRef.Namespace)

	// Check remediation
	assert.NotEmpty(t, entry.Remediation.Summary)
	assert.NotEmpty(t, entry.Remediation.Steps)

	// Check tags
	assert.Equal(t, []string{"network", "ingress"}, entry.Tags)

	// Check last observed is set
	assert.False(t, entry.LastObserved.IsZero())
}

func TestReportReconciler_ScopedName(t *testing.T) {
	tests := []struct {
		name           string
		detailLevel    types.DetailLevel
		constraintNS   string
		viewerNS       string
		constraintName string
		expectedName   string
	}{
		{
			name:           "summary level, same namespace",
			detailLevel:    types.DetailLevelSummary,
			constraintNS:   "team-alpha",
			viewerNS:       "team-alpha",
			constraintName: "my-policy",
			expectedName:   "my-policy",
		},
		{
			name:           "summary level, cross namespace",
			detailLevel:    types.DetailLevelSummary,
			constraintNS:   "kube-system",
			viewerNS:       "team-alpha",
			constraintName: "cluster-policy",
			expectedName:   "cluster-policy", // Shows "cluster-policy" as redacted name
		},
		{
			name:           "summary level, cluster-scoped",
			detailLevel:    types.DetailLevelSummary,
			constraintNS:   "",
			viewerNS:       "team-alpha",
			constraintName: "global-webhook",
			expectedName:   "global-webhook",
		},
		{
			name:           "detailed level, cross namespace",
			detailLevel:    types.DetailLevelDetailed,
			constraintNS:   "kube-system",
			viewerNS:       "team-alpha",
			constraintName: "detailed-policy",
			expectedName:   "detailed-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := &ReportReconciler{
				opts: ReportReconcilerOptions{
					DefaultDetailLevel: tt.detailLevel,
				},
			}

			c := types.Constraint{
				Name:      tt.constraintName,
				Namespace: tt.constraintNS,
			}

			result := rr.scopedName(c, tt.viewerNS)
			assert.Equal(t, tt.expectedName, result)
		})
	}
}

func TestSeverityOrder(t *testing.T) {
	assert.Less(t, severityOrder("Critical"), severityOrder("Warning"))
	assert.Less(t, severityOrder("Warning"), severityOrder("Info"))
	assert.Less(t, severityOrder("Info"), severityOrder("Unknown"))
}

func TestGvrToAPIVersion(t *testing.T) {
	tests := []struct {
		gvr      schema.GroupVersionResource
		expected string
	}{
		{
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			expected: "v1",
		},
		{
			gvr:      schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			expected: "networking.k8s.io/v1",
		},
		{
			gvr:      schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			expected: "apps/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := gvrToAPIVersion(tt.gvr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGvrToKindName(t *testing.T) {
	tests := []struct {
		resource string
		expected string
	}{
		{"networkpolicies", "NetworkPolicy"},
		{"resourcequotas", "ResourceQuota"},
		{"limitranges", "LimitRange"},
		{"validatingwebhookconfigurations", "ValidatingWebhookConfiguration"},
		{"mutatingwebhookconfigurations", "MutatingWebhookConfiguration"},
		{"ciliumnetworkpolicies", "CiliumNetworkPolicy"},
		{"pods", "Pod"},
		{"deployments", "Deployment"},
		{"statefulsets", "StatefulSet"},
		{"customresources", "Customresource"}, // Generic handling
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			gvr := schema.GroupVersionResource{Resource: tt.resource}
			result := gvrToKindName(gvr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultReportReconcilerOptions(t *testing.T) {
	opts := DefaultReportReconcilerOptions()

	assert.Equal(t, 10*1000*1000*1000, int(opts.DebounceDuration)) // 10 seconds
	assert.Equal(t, types.DetailLevelSummary, opts.DefaultDetailLevel)
	assert.Equal(t, "your platform team", opts.DefaultContact)
}

func TestReportReconciler_ExtractResourceMetrics(t *testing.T) {
	rr := &ReportReconciler{}

	c := types.Constraint{
		Details: map[string]interface{}{
			"resources": map[string]interface{}{
				"cpu": map[string]interface{}{
					"hard":    "4",
					"used":    "3.2",
					"percent": 80,
				},
				"memory": map[string]interface{}{
					"hard":    "8Gi",
					"used":    "6Gi",
					"percent": 75.5,
				},
				"pods": map[string]interface{}{
					"hard":    "100",
					"used":    "50",
					"percent": 50,
				},
			},
		},
	}

	metrics := rr.extractResourceMetrics(c)

	require.NotNil(t, metrics)
	require.Len(t, metrics, 3)

	cpu := metrics["cpu"]
	assert.Equal(t, "4", cpu.Hard)
	assert.Equal(t, "3.2", cpu.Used)
	assert.Equal(t, float64(80), cpu.PercentUsed)
	assert.Equal(t, "cores", cpu.Unit)

	memory := metrics["memory"]
	assert.Equal(t, "8Gi", memory.Hard)
	assert.Equal(t, "6Gi", memory.Used)
	assert.Equal(t, 75.5, memory.PercentUsed)
	assert.Equal(t, "bytes", memory.Unit)

	pods := metrics["pods"]
	assert.Equal(t, "100", pods.Hard)
	assert.Equal(t, "50", pods.Used)
	assert.Equal(t, float64(50), pods.PercentUsed)
	assert.Equal(t, "count", pods.Unit)
}

func TestReportReconciler_ExtractResourceMetrics_NilDetails(t *testing.T) {
	rr := &ReportReconciler{}

	c := types.Constraint{
		Details: nil,
	}

	metrics := rr.extractResourceMetrics(c)
	assert.Nil(t, metrics)
}

// --- New tests to boost coverage ---

func TestScopedMessage_AllDetailLevels(t *testing.T) {
	tests := []struct {
		name         string
		detailLevel  types.DetailLevel
		constraintNS string
		viewerNS     string
		summary      string
		ctType       types.ConstraintType
		expected     string
	}{
		{
			name:         "summary level cross namespace returns generic",
			detailLevel:  types.DetailLevelSummary,
			constraintNS: "kube-system",
			viewerNS:     "team-alpha",
			summary:      "Specific details about policy",
			ctType:       types.ConstraintTypeNetworkEgress,
			expected:     "Outbound network traffic is restricted by a network policy",
		},
		{
			name:         "summary level same namespace returns actual summary",
			detailLevel:  types.DetailLevelSummary,
			constraintNS: "team-alpha",
			viewerNS:     "team-alpha",
			summary:      "My specific summary",
			ctType:       types.ConstraintTypeNetworkEgress,
			expected:     "My specific summary",
		},
		{
			name:         "summary level cluster-scoped returns actual summary",
			detailLevel:  types.DetailLevelSummary,
			constraintNS: "",
			viewerNS:     "team-alpha",
			summary:      "Cluster policy summary",
			ctType:       types.ConstraintTypeAdmission,
			expected:     "Cluster policy summary",
		},
		{
			name:         "detailed level returns actual summary",
			detailLevel:  types.DetailLevelDetailed,
			constraintNS: "kube-system",
			viewerNS:     "team-alpha",
			summary:      "Detailed summary",
			ctType:       types.ConstraintTypeNetworkIngress,
			expected:     "Detailed summary",
		},
		{
			name:         "empty summary falls back to generic",
			detailLevel:  types.DetailLevelDetailed,
			constraintNS: "team-alpha",
			viewerNS:     "team-alpha",
			summary:      "",
			ctType:       types.ConstraintTypeResourceLimit,
			expected:     "Resource quotas or limits apply to this namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := &ReportReconciler{
				opts: ReportReconcilerOptions{
					DefaultDetailLevel: tt.detailLevel,
				},
			}

			c := types.Constraint{
				Name:           "test-policy",
				Namespace:      tt.constraintNS,
				Summary:        tt.summary,
				ConstraintType: tt.ctType,
			}

			result := rr.scopedMessage(c, tt.viewerNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGvrToKindName_GenericFallback(t *testing.T) {
	tests := []struct {
		resource string
		expected string
	}{
		{"ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy"},
		{"fooconfigs", "Fooconfig"}, // generic: strips s, capitalizes
		{"x", "X"},                  // single char, no trailing s
		{"", ""},                    // empty string
		{"mesh", "Mesh"},            // no trailing s, just capitalize
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			gvr := schema.GroupVersionResource{Resource: tt.resource}
			result := gvrToKindName(gvr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityOrder_AllValues(t *testing.T) {
	assert.Equal(t, 0, severityOrder("Critical"))
	assert.Equal(t, 1, severityOrder("Warning"))
	assert.Equal(t, 2, severityOrder("Info"))
	assert.Equal(t, 3, severityOrder("Unknown"))
	assert.Equal(t, 3, severityOrder(""))
	assert.Equal(t, 3, severityOrder("garbage"))
}

func TestReportReconciler_BuildReportStatus_EmptyConstraints(t *testing.T) {
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelSummary,
			DefaultContact:     "platform@example.com",
		},
	}

	status := rr.buildReportStatus(nil, "team-alpha")

	assert.Equal(t, 0, status.ConstraintCount)
	assert.Equal(t, 0, status.CriticalCount)
	assert.Equal(t, 0, status.WarningCount)
	assert.Equal(t, 0, status.InfoCount)
	assert.Empty(t, status.Constraints)
	require.NotNil(t, status.MachineReadable)
	assert.Equal(t, "1", status.MachineReadable.SchemaVersion)
}

func TestReportReconciler_BuildMachineEntry_WithResourceMetrics(t *testing.T) {
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelDetailed,
		},
	}

	c := types.Constraint{
		UID:            k8stypes.UID("quota-uid"),
		Name:           "cpu-quota",
		Namespace:      "team-alpha",
		ConstraintType: types.ConstraintTypeResourceLimit,
		Severity:       types.SeverityWarning,
		Effect:         "limit",
		Source:         schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
		Details: map[string]interface{}{
			"resources": map[string]interface{}{
				"cpu": map[string]interface{}{
					"hard":    "8",
					"used":    "7",
					"percent": 87.5,
				},
			},
		},
	}

	entry := rr.buildMachineEntry(c, "team-alpha")

	require.NotNil(t, entry.Metrics)
	cpuMetric, ok := entry.Metrics["cpu"]
	require.True(t, ok)
	assert.Equal(t, "8", cpuMetric.Hard)
	assert.Equal(t, "7", cpuMetric.Used)
	assert.Equal(t, 87.5, cpuMetric.PercentUsed)
	assert.Equal(t, "cores", cpuMetric.Unit)
}

func TestReportReconciler_BuildMachineEntry_NoMetricsForNonResourceLimit(t *testing.T) {
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelDetailed,
		},
	}

	c := types.Constraint{
		UID:            k8stypes.UID("net-uid"),
		Name:           "test-netpol",
		Namespace:      "team-alpha",
		ConstraintType: types.ConstraintTypeNetworkEgress,
		Severity:       types.SeverityWarning,
		Effect:         "restrict",
		Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	entry := rr.buildMachineEntry(c, "team-alpha")

	assert.Nil(t, entry.Metrics, "Non-resource-limit constraint should not have metrics")
}

func TestNewReportReconciler(t *testing.T) {
	idx := &indexer.Indexer{}
	logger := zap.NewNop()
	opts := DefaultReportReconcilerOptions()

	rr := NewReportReconciler(nil, idx, logger, opts, nil, nil, nil)

	require.NotNil(t, rr)
	assert.NotNil(t, rr.remediationBuilder)
	assert.NotNil(t, rr.lastReconcile)
	assert.NotNil(t, rr.pendingTriggers)
	assert.Equal(t, types.DetailLevelSummary, rr.opts.DefaultDetailLevel)
}

func TestNewReportReconciler_ZeroValues(t *testing.T) {
	idx := &indexer.Indexer{}
	logger := zap.NewNop()
	opts := ReportReconcilerOptions{} // all zero

	rr := NewReportReconciler(nil, idx, logger, opts, nil, nil, nil)

	// Should apply defaults
	assert.Equal(t, 10*time.Second, rr.opts.DebounceDuration)
	assert.Equal(t, types.DetailLevelSummary, rr.opts.DefaultDetailLevel)
}

func TestReportReconciler_OnIndexChange(t *testing.T) {
	rr := &ReportReconciler{
		logger:          zap.NewNop(),
		pendingTriggers: make(map[string]bool),
		lastReconcile:   make(map[string]time.Time),
	}

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "test-policy",
			Namespace:          "team-alpha",
			AffectedNamespaces: []string{"team-alpha", "team-beta"},
		},
	}

	rr.OnIndexChange(event)

	// Should have pending triggers for all namespaces
	rr.mu.Lock()
	defer rr.mu.Unlock()
	assert.True(t, rr.pendingTriggers["team-alpha"])
	assert.True(t, rr.pendingTriggers["team-beta"])
}

func TestReportReconciler_OnIndexChange_ClusterScoped(t *testing.T) {
	rr := &ReportReconciler{
		logger:          zap.NewNop(),
		pendingTriggers: make(map[string]bool),
		lastReconcile:   make(map[string]time.Time),
	}

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "cluster-policy",
			Namespace:          "", // cluster-scoped
			AffectedNamespaces: []string{"ns-a", "ns-b", "ns-c"},
		},
	}

	rr.OnIndexChange(event)

	rr.mu.Lock()
	defer rr.mu.Unlock()
	assert.True(t, rr.pendingTriggers["ns-a"])
	assert.True(t, rr.pendingTriggers["ns-b"])
	assert.True(t, rr.pendingTriggers["ns-c"])
	// No namespace "" should be in pendingTriggers
	assert.False(t, rr.pendingTriggers[""])
}

func TestReportReconciler_OnIndexChange_ClusterScoped_NoAffectedNamespaces(t *testing.T) {
	rr := &ReportReconciler{
		logger:          zap.NewNop(),
		pendingTriggers: make(map[string]bool),
		lastReconcile:   make(map[string]time.Time),
	}

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			Name:               "webhook-policy",
			Namespace:          "", // cluster-scoped
			AffectedNamespaces: nil,
		},
	}

	rr.OnIndexChange(event)

	rr.mu.Lock()
	defer rr.mu.Unlock()
	// Should have set clusterWideTriggered instead of adding empty namespace trigger
	assert.True(t, rr.clusterWideTriggered)
	assert.Empty(t, rr.pendingTriggers)
}

func TestReportReconciler_ExtractResourceMetrics_NonMapEntry(t *testing.T) {
	rr := &ReportReconciler{}

	c := types.Constraint{
		Details: map[string]interface{}{
			"resources": map[string]interface{}{
				"cpu":     "not-a-map",
				"memory":  42,
				"storage": map[string]interface{}{"hard": "100Gi", "used": "50Gi", "percent": 50},
			},
		},
	}

	metrics := rr.extractResourceMetrics(c)
	require.NotNil(t, metrics)
	assert.Len(t, metrics, 1)
	assert.Contains(t, metrics, "storage")
}

func TestReportReconciler_ExtractResourceMetrics_NoResources(t *testing.T) {
	rr := &ReportReconciler{}

	c := types.Constraint{
		Details: map[string]interface{}{
			"other": "data",
		},
	}

	metrics := rr.extractResourceMetrics(c)
	assert.Nil(t, metrics)
}

func TestConstraintToMissingResourceEntry(t *testing.T) {
	rb := NewRemediationBuilder("platform@example.com")
	workload := &unstructured.Unstructured{}
	workload.SetKind("Deployment")
	workload.SetName("my-app")

	c := types.Constraint{
		UID:            k8stypes.UID("missing:prometheus-monitor:team-alpha/my-app"),
		Name:           "missing-prometheus-monitor-my-app",
		Namespace:      "team-alpha",
		ConstraintType: types.ConstraintTypeMissing,
		Severity:       types.SeverityWarning,
		Details: map[string]interface{}{
			"expectedKind":       "ServiceMonitor",
			"expectedAPIVersion": "monitoring.coreos.com/v1",
			"reason":             "Workload has metrics port but no monitor",
		},
	}

	entry := constraintToMissingResourceEntry(c, workload, rb)

	assert.Equal(t, "ServiceMonitor", entry.ExpectedKind)
	assert.Equal(t, "monitoring.coreos.com/v1", entry.ExpectedAPIVersion)
	assert.Equal(t, "Workload has metrics port but no monitor", entry.Reason)
	assert.Equal(t, "Warning", entry.Severity)
	assert.Equal(t, "Deployment", entry.ForWorkload.Kind)
	assert.Equal(t, "my-app", entry.ForWorkload.Name)
	assert.NotEmpty(t, entry.Remediation.Summary)
}

func TestConstraintToMissingResourceEntry_NilWorkload(t *testing.T) {
	rb := NewRemediationBuilder("platform@example.com")

	c := types.Constraint{
		Severity: types.SeverityWarning,
		Details: map[string]interface{}{
			"expectedKind": "ServiceMonitor",
		},
	}

	entry := constraintToMissingResourceEntry(c, nil, rb)

	assert.Equal(t, "ServiceMonitor", entry.ExpectedKind)
	assert.Empty(t, entry.ForWorkload.Kind)
	assert.Empty(t, entry.ForWorkload.Name)
}

func TestConstraintToMissingResourceEntry_NilRemediationBuilder(t *testing.T) {
	workload := &unstructured.Unstructured{}
	workload.SetKind("StatefulSet")
	workload.SetName("db")

	c := types.Constraint{
		Severity: types.SeverityWarning,
	}

	entry := constraintToMissingResourceEntry(c, workload, nil)

	assert.Equal(t, "Warning", entry.Severity)
	assert.Equal(t, "StatefulSet", entry.ForWorkload.Kind)
}

func TestEvaluateMissingResources_NilEvaluator(t *testing.T) {
	rr := &ReportReconciler{
		logger: zap.NewNop(),
	}

	result := rr.evaluateMissingResources("team-alpha")
	assert.Empty(t, result)
	assert.NotNil(t, result) // Should be empty slice, not nil
}

func TestBuildReportStatus_WithMissingResources(t *testing.T) {
	// This test verifies that MissingResources is present in machine-readable output.
	// With nil evaluator, it should be an empty slice.
	rr := &ReportReconciler{
		logger:             zap.NewNop(),
		remediationBuilder: NewRemediationBuilder("platform@example.com"),
		opts: ReportReconcilerOptions{
			DefaultDetailLevel: types.DetailLevelSummary,
			DefaultContact:     "platform@example.com",
		},
	}

	constraints := []types.Constraint{
		{
			UID:            k8stypes.UID("uid-1"),
			Name:           "test-policy",
			Namespace:      "team-alpha",
			ConstraintType: types.ConstraintTypeNetworkEgress,
			Severity:       types.SeverityWarning,
			Source:         schema.GroupVersionResource{Resource: "networkpolicies"},
		},
	}

	status := rr.buildReportStatus(constraints, "team-alpha")

	require.NotNil(t, status.MachineReadable)
	assert.NotNil(t, status.MachineReadable.MissingResources)
	assert.Empty(t, status.MachineReadable.MissingResources)
}
