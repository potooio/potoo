package gatekeeper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/potooio/potoo/internal/types"
)

func loadTestData(t *testing.T, filename string) *unstructured.Unstructured {
	t.Helper()
	path := filepath.Join("testdata", filename)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read testdata file")

	obj := &unstructured.Unstructured{}
	err = yaml.Unmarshal(data, &obj.Object)
	require.NoError(t, err, "failed to unmarshal testdata")

	return obj
}

func TestAdapter_Name(t *testing.T) {
	adapter := New()
	assert.Equal(t, "gatekeeper", adapter.Name())
}

func TestAdapter_Handles(t *testing.T) {
	adapter := New()
	gvrs := adapter.Handles()

	require.Len(t, gvrs, 1)
	assert.Equal(t, GatekeeperConstraintGroup, gvrs[0].Group)
	assert.Equal(t, DefaultVersion, gvrs[0].Version)
	assert.Equal(t, "*", gvrs[0].Resource)
}

func TestAdapter_Parse_RequiredLabels(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "k8srequiredlabels.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]

	// Identity
	assert.Equal(t, "require-team-label", c.Name)
	assert.Empty(t, c.Namespace) // Gatekeeper constraints are cluster-scoped

	// Severity from enforcementAction=deny
	assert.Equal(t, types.SeverityCritical, c.Severity)
	assert.Equal(t, "deny", c.Effect)
	assert.Equal(t, types.ConstraintTypeAdmission, c.ConstraintType)

	// Affected namespaces
	assert.ElementsMatch(t, []string{"production", "staging"}, c.AffectedNamespaces)

	// Resource targets
	require.Len(t, c.ResourceTargets, 2)
	assert.Contains(t, c.ResourceTargets[0].Resources, "pods")
	assert.Contains(t, c.ResourceTargets[1].Resources, "deployments")

	// Workload selector
	require.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "helm", c.WorkloadSelector.MatchLabels["app.kubernetes.io/managed-by"])

	// Summary should mention the constraint
	assert.Contains(t, c.Summary, "K8sRequiredLabels")
	assert.Contains(t, c.Summary, "require-team-label")
	assert.Contains(t, c.Summary, "rejects")

	// Details should have parameters
	details := c.Details
	assert.Equal(t, "deny", details["enforcementAction"])
	assert.NotNil(t, details["parameters"])
	assert.NotNil(t, details["excludedNamespaces"])

	// Tags
	assert.Contains(t, c.Tags, "gatekeeper")
	assert.Contains(t, c.Tags, "admission")
	assert.Contains(t, c.Tags, "blocking")

	// Remediation
	require.NotEmpty(t, c.Remediation)
	assert.Equal(t, "kubectl", c.Remediation[0].Type)
}

func TestAdapter_Parse_UniqueIngressHost(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "k8suniqueingresshost.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]

	// Severity from enforcementAction=warn
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "warn", c.Effect)

	// No namespace restriction
	assert.Empty(t, c.AffectedNamespaces)

	// Resource targets
	require.Len(t, c.ResourceTargets, 1)
	assert.Contains(t, c.ResourceTargets[0].APIGroups, "networking.k8s.io")
	assert.Contains(t, c.ResourceTargets[0].Resources, "ingresss") // Automatic pluralization

	// Summary
	assert.Contains(t, c.Summary, "warns on")

	// Tags
	assert.Contains(t, c.Tags, "warning")
	assert.NotContains(t, c.Tags, "blocking")
}

func TestAdapter_Parse_DryRun(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "deny_all.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]

	// Severity from enforcementAction=dryrun
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "audit", c.Effect)

	// Namespace selector (not affected namespaces list)
	assert.Empty(t, c.AffectedNamespaces)
	require.NotNil(t, c.NamespaceSelector)
	assert.Equal(t, "production", c.NamespaceSelector.MatchLabels["environment"])

	// Summary
	assert.Contains(t, c.Summary, "audits")

	// Tags
	assert.Contains(t, c.Tags, "audit")
}

func TestAdapter_Parse_MissingSpec(t *testing.T) {
	adapter := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sTest",
			"metadata": map[string]interface{}{
				"name": "test",
			},
		},
	}

	_, err := adapter.Parse(context.Background(), obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing spec")
}

func TestAdapter_Parse_DefaultEnforcementAction(t *testing.T) {
	adapter := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sTest",
			"metadata": map[string]interface{}{
				"name": "test",
				"uid":  "test-uid",
			},
			"spec": map[string]interface{}{
				// No enforcementAction specified - should default to deny
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	// Default should be deny/Critical
	assert.Equal(t, types.SeverityCritical, constraints[0].Severity)
	assert.Equal(t, "deny", constraints[0].Effect)
}

func TestMapEnforcementToSeverity(t *testing.T) {
	tests := []struct {
		action   string
		expected types.Severity
	}{
		{"deny", types.SeverityCritical},
		{"DENY", types.SeverityCritical},
		{"warn", types.SeverityWarning},
		{"WARN", types.SeverityWarning},
		{"dryrun", types.SeverityInfo},
		{"DRYRUN", types.SeverityInfo},
		{"unknown", types.SeverityCritical}, // Unknown defaults to Critical
		{"", types.SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapEnforcementToSeverity(tc.action))
		})
	}
}
