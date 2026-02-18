package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
)

func TestGvrToKind(t *testing.T) {
	tests := []struct {
		name     string
		gvr      schema.GroupVersionResource
		expected string
	}{
		{
			name:     "networkpolicies",
			gvr:      schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			expected: "NetworkPolicy",
		},
		{
			name:     "resourcequotas",
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
			expected: "ResourceQuota",
		},
		{
			name:     "limitranges",
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: "limitranges"},
			expected: "LimitRange",
		},
		{
			name:     "validatingwebhookconfigurations",
			gvr:      schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
			expected: "ValidatingWebhookConfiguration",
		},
		{
			name:     "mutatingwebhookconfigurations",
			gvr:      schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"},
			expected: "MutatingWebhookConfiguration",
		},
		{
			name:     "ciliumnetworkpolicies",
			gvr:      schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
			expected: "CiliumNetworkPolicy",
		},
		{
			name:     "ciliumclusterwidenetworkpolicies",
			gvr:      schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"},
			expected: "CiliumClusterwideNetworkPolicy",
		},
		{
			name:     "generic fallback strips trailing s and capitalizes",
			gvr:      schema.GroupVersionResource{Group: "custom.io", Version: "v1", Resource: "fooconfigs"},
			expected: "Fooconfig",
		},
		{
			name:     "generic fallback single char resource",
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: "x"},
			expected: "X",
		},
		{
			name:     "generic fallback resource not ending in s keeps full name",
			gvr:      schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "mesh"},
			expected: "Mesh",
		},
		{
			name:     "generic fallback empty resource",
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gvrToKind(tt.gvr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGvrToAPIVersion(t *testing.T) {
	tests := []struct {
		name     string
		gvr      schema.GroupVersionResource
		expected string
	}{
		{
			name:     "core group returns version only",
			gvr:      schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
			expected: "v1",
		},
		{
			name:     "non-core group returns group/version",
			gvr:      schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
			expected: "networking.k8s.io/v1",
		},
		{
			name:     "admissionregistration group",
			gvr:      schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
			expected: "admissionregistration.k8s.io/v1",
		},
		{
			name:     "cilium group v2",
			gvr:      schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
			expected: "cilium.io/v2",
		},
		{
			name:     "custom group with beta version",
			gvr:      schema.GroupVersionResource{Group: "custom.example.com", Version: "v1beta1", Resource: "widgets"},
			expected: "custom.example.com/v1beta1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gvrToAPIVersion(tt.gvr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractMetrics(t *testing.T) {
	t.Run("nil details returns nil", func(t *testing.T) {
		c := types.Constraint{
			Details: nil,
		}
		result := extractMetrics(c)
		assert.Nil(t, result)
	})

	t.Run("missing resources key returns nil", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"something_else": "value",
			},
		}
		result := extractMetrics(c)
		assert.Nil(t, result)
	})

	t.Run("resources key wrong type returns nil", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": "not-a-map",
			},
		}
		result := extractMetrics(c)
		assert.Nil(t, result)
	})

	t.Run("valid resources with int percent", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"cpu": map[string]interface{}{
						"hard":    "4",
						"used":    "3.8",
						"percent": 95,
					},
				},
			},
		}
		result := extractMetrics(c)
		require.NotNil(t, result)
		require.Contains(t, result, "cpu")

		cpuMetric := result["cpu"]
		assert.Equal(t, "4", cpuMetric.Hard)
		assert.Equal(t, "3.8", cpuMetric.Used)
		assert.Equal(t, "cores", cpuMetric.Unit)
		assert.Equal(t, float64(95), cpuMetric.PercentUsed)
	})

	t.Run("valid resources with float percent", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"memory": map[string]interface{}{
						"hard":    "8Gi",
						"used":    "6.5Gi",
						"percent": 81.25,
					},
				},
			},
		}
		result := extractMetrics(c)
		require.NotNil(t, result)
		require.Contains(t, result, "memory")

		memMetric := result["memory"]
		assert.Equal(t, "8Gi", memMetric.Hard)
		assert.Equal(t, "6.5Gi", memMetric.Used)
		assert.Equal(t, "bytes", memMetric.Unit)
		assert.Equal(t, 81.25, memMetric.PercentUsed)
	})

	t.Run("multiple resources in single constraint", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"cpu": map[string]interface{}{
						"hard":    "4",
						"used":    "2",
						"percent": 50,
					},
					"memory": map[string]interface{}{
						"hard":    "16Gi",
						"used":    "12Gi",
						"percent": 75.0,
					},
				},
			},
		}
		result := extractMetrics(c)
		require.NotNil(t, result)
		assert.Len(t, result, 2)
		assert.Contains(t, result, "cpu")
		assert.Contains(t, result, "memory")
		assert.Equal(t, "cores", result["cpu"].Unit)
		assert.Equal(t, "bytes", result["memory"].Unit)
	})

	t.Run("resource entry with non-map value is skipped", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"cpu":     "invalid-not-a-map",
					"memory":  42,
					"storage": map[string]interface{}{"hard": "100Gi", "used": "50Gi", "percent": 50},
				},
			},
		}
		result := extractMetrics(c)
		require.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Contains(t, result, "storage")
	})

	t.Run("resource entry with missing fields uses zero values", func(t *testing.T) {
		c := types.Constraint{
			Details: map[string]interface{}{
				"resources": map[string]interface{}{
					"cpu": map[string]interface{}{},
				},
			},
		}
		result := extractMetrics(c)
		require.NotNil(t, result)
		require.Contains(t, result, "cpu")

		cpuMetric := result["cpu"]
		assert.Equal(t, "", cpuMetric.Hard)
		assert.Equal(t, "", cpuMetric.Used)
		assert.Equal(t, "cores", cpuMetric.Unit)
		assert.Equal(t, float64(0), cpuMetric.PercentUsed)
	})
}

func TestGuessUnit(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		expected     string
	}{
		{
			name:         "cpu exact match",
			resourceName: "cpu",
			expected:     "cores",
		},
		{
			name:         "cpu with prefix suffix",
			resourceName: "requests.cpu",
			expected:     "cores",
		},
		{
			name:         "limits.cpu suffix",
			resourceName: "limits.cpu",
			expected:     "cores",
		},
		{
			name:         "memory exact match",
			resourceName: "memory",
			expected:     "bytes",
		},
		{
			name:         "memory with prefix suffix",
			resourceName: "requests.memory",
			expected:     "bytes",
		},
		{
			name:         "limits.memory suffix",
			resourceName: "limits.memory",
			expected:     "bytes",
		},
		{
			name:         "storage contains match",
			resourceName: "storage",
			expected:     "bytes",
		},
		{
			name:         "ephemeral-storage contains match",
			resourceName: "ephemeral-storage",
			expected:     "bytes",
		},
		{
			name:         "requests.storage contains match",
			resourceName: "requests.storage",
			expected:     "bytes",
		},
		{
			name:         "default for pods",
			resourceName: "pods",
			expected:     "count",
		},
		{
			name:         "default for services",
			resourceName: "services",
			expected:     "count",
		},
		{
			name:         "default for configmaps",
			resourceName: "configmaps",
			expected:     "count",
		},
		{
			name:         "default for unknown resource",
			resourceName: "custom-thing",
			expected:     "count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := guessUnit(tt.resourceName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScopedConstraintName(t *testing.T) {
	tests := []struct {
		name            string
		constraint      types.Constraint
		level           types.DetailLevel
		viewerNamespace string
		expected        string
	}{
		{
			name: "summary level same namespace does not redact",
			constraint: types.Constraint{
				Name:      "my-policy",
				Namespace: "team-alpha",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        "my-policy",
		},
		{
			name: "summary level cross namespace redacts",
			constraint: types.Constraint{
				Name:      "secret-policy",
				Namespace: "kube-system",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        "redacted",
		},
		{
			name: "summary level cluster-scoped constraint redacts",
			constraint: types.Constraint{
				Name:      "cluster-wide-policy",
				Namespace: "",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        "redacted",
		},
		{
			name: "detailed level same namespace shows name",
			constraint: types.Constraint{
				Name:      "my-policy",
				Namespace: "team-alpha",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        "my-policy",
		},
		{
			name: "detailed level cross namespace shows name",
			constraint: types.Constraint{
				Name:      "cross-ns-policy",
				Namespace: "kube-system",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        "cross-ns-policy",
		},
		{
			name: "detailed level cluster-scoped shows name",
			constraint: types.Constraint{
				Name:      "cluster-policy",
				Namespace: "",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        "cluster-policy",
		},
		{
			name: "full level always shows name",
			constraint: types.Constraint{
				Name:      "any-policy",
				Namespace: "other-ns",
			},
			level:           types.DetailLevelFull,
			viewerNamespace: "team-alpha",
			expected:        "any-policy",
		},
		{
			name: "full level cluster-scoped shows name",
			constraint: types.Constraint{
				Name:      "cluster-wide",
				Namespace: "",
			},
			level:           types.DetailLevelFull,
			viewerNamespace: "team-alpha",
			expected:        "cluster-wide",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scopedConstraintName(tt.constraint, tt.level, tt.viewerNamespace)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCanShowNamespace(t *testing.T) {
	tests := []struct {
		name            string
		constraint      types.Constraint
		level           types.DetailLevel
		viewerNamespace string
		expected        bool
	}{
		// Summary level tests
		{
			name: "summary same namespace shows",
			constraint: types.Constraint{
				Namespace: "team-alpha",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
		{
			name: "summary cross namespace hides",
			constraint: types.Constraint{
				Namespace: "kube-system",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        false,
		},
		{
			name: "summary cluster-scoped hides",
			constraint: types.Constraint{
				Namespace: "",
			},
			level:           types.DetailLevelSummary,
			viewerNamespace: "team-alpha",
			expected:        false,
		},
		// Detailed level tests
		{
			name: "detailed same namespace shows",
			constraint: types.Constraint{
				Namespace: "team-alpha",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
		{
			name: "detailed cross namespace hides",
			constraint: types.Constraint{
				Namespace: "kube-system",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        false,
		},
		{
			name: "detailed cluster-scoped shows",
			constraint: types.Constraint{
				Namespace: "",
			},
			level:           types.DetailLevelDetailed,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
		// Full level tests
		{
			name: "full same namespace shows",
			constraint: types.Constraint{
				Namespace: "team-alpha",
			},
			level:           types.DetailLevelFull,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
		{
			name: "full cross namespace shows",
			constraint: types.Constraint{
				Namespace: "kube-system",
			},
			level:           types.DetailLevelFull,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
		{
			name: "full cluster-scoped shows",
			constraint: types.Constraint{
				Namespace: "",
			},
			level:           types.DetailLevelFull,
			viewerNamespace: "team-alpha",
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canShowNamespace(tt.constraint, tt.level, tt.viewerNamespace)
			assert.Equal(t, tt.expected, result)
		})
	}
}
