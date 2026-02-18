package istio

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/potooio/potoo/internal/types"
)

func loadFixture(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	obj := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal(data, &obj.Object))
	return obj
}

func TestName(t *testing.T) {
	a := New()
	assert.Equal(t, "istio", a.Name())
}

func TestHandles(t *testing.T) {
	a := New()
	gvrs := a.Handles()
	assert.Len(t, gvrs, 3)
	assert.Equal(t, "security.istio.io", gvrs[0].Group)
	assert.Equal(t, "authorizationpolicies", gvrs[0].Resource)
	assert.Equal(t, "security.istio.io", gvrs[1].Group)
	assert.Equal(t, "peerauthentications", gvrs[1].Resource)
	assert.Equal(t, "networking.istio.io", gvrs[2].Group)
	assert.Equal(t, "sidecars", gvrs[2].Resource)
}

// --- AuthorizationPolicy tests ---

func TestAuthorizationPolicy_Deny(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_deny.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeMeshPolicy, c.ConstraintType)
	assert.Equal(t, types.SeverityCritical, c.Severity)
	assert.Equal(t, "deny", c.Effect)
	assert.Equal(t, "deny-external", c.Name)
	assert.Equal(t, "production", c.Namespace)
	assert.Equal(t, []string{"production"}, c.AffectedNamespaces)
	assert.Contains(t, c.Summary, "denies traffic")
	assert.Contains(t, c.Summary, "namespace/untrusted")
	assert.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "web", c.WorkloadSelector.MatchLabels["app"])
	assert.Contains(t, c.Tags, "mesh")
	assert.Contains(t, c.Tags, "istio")
	assert.Contains(t, c.Tags, "authorization")
	assert.Equal(t, gvrAuthorizationPolicy, c.Source)
	assert.NotNil(t, c.RawObject)
	assert.Equal(t, "DENY", c.Details["action"])
}

func TestAuthorizationPolicy_Allow(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_allow.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeMeshPolicy, c.ConstraintType)
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Contains(t, c.Summary, "restricts traffic")
	assert.Contains(t, c.Summary, "cluster.local/ns/production/sa/api-gateway")
	assert.Equal(t, "ALLOW", c.Details["action"])
}

func TestAuthorizationPolicy_Custom(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_custom.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Contains(t, c.Summary, "port/8080")
	assert.Equal(t, "CUSTOM", c.Details["action"])
}

func TestAuthorizationPolicy_MultiRule(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_multirule.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityCritical, c.Severity)
	assert.Equal(t, "deny", c.Effect)
	// Should contain sources from both rules.
	assert.Contains(t, c.Summary, "namespace/external")
	assert.Equal(t, 2, c.Details["ruleCount"])
	// No selector → nil WorkloadSelector.
	assert.Nil(t, c.WorkloadSelector)
}

func TestAuthorizationPolicy_NoAction(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_no_action.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	// Default action is ALLOW.
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Equal(t, "ALLOW", c.Details["action"])
}

func TestAuthorizationPolicy_DenyEmptyRules(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_empty_rules.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityCritical, c.Severity)
	assert.Equal(t, "deny", c.Effect)
	assert.Contains(t, c.Summary, "no rules")
	assert.Contains(t, c.Summary, "no-op")
}

func TestAuthorizationPolicy_AllowEmptyRules(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_allow_empty_rules.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Contains(t, c.Summary, "denies all traffic")
}

// --- PeerAuthentication tests ---

func TestPeerAuthentication_Strict(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_strict.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeMeshPolicy, c.ConstraintType)
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "require", c.Effect)
	assert.Contains(t, c.Summary, "STRICT")
	assert.Contains(t, c.Summary, "workload scope")
	assert.Equal(t, "STRICT", c.Details["mtlsMode"])
	assert.Equal(t, "workload", c.Details["scope"])
	assert.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "api", c.WorkloadSelector.MatchLabels["app"])
	assert.Contains(t, c.Tags, "mtls")
	assert.Equal(t, gvrPeerAuthentication, c.Source)
}

func TestPeerAuthentication_Permissive(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_permissive.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Contains(t, c.Summary, "PERMISSIVE")
	assert.Equal(t, "PERMISSIVE", c.Details["mtlsMode"])
}

func TestPeerAuthentication_Disable(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_disable.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "warn", c.Effect)
	assert.Contains(t, c.Summary, "DISABLE")
}

func TestPeerAuthentication_MeshWide(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_meshwide.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, "mesh-wide", c.Details["scope"])
	assert.Contains(t, c.Summary, "mesh-wide")
	assert.Nil(t, c.WorkloadSelector)
	assert.Equal(t, "istio-system", c.Namespace)
}

func TestPeerAuthentication_EmptySpec(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_empty.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Nil(t, c.WorkloadSelector)
}

func TestPeerAuthentication_PortLevel(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/peerauthentication_port_level.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	// Main mTLS mode is STRICT.
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.Equal(t, "require", c.Effect)
	// Should record that portLevelMtls exists.
	assert.Equal(t, true, c.Details["hasPortLevelMtls"])
}

// --- Sidecar tests ---

func TestSidecar_EgressRestrict(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/sidecar_egress_restrict.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeMeshPolicy, c.ConstraintType)
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "restrict", c.Effect)
	assert.Contains(t, c.Summary, "restricts egress")
	assert.Contains(t, c.Summary, "./*")
	assert.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "web", c.WorkloadSelector.MatchLabels["app"])
	hosts, ok := c.Details["egressHosts"].([]string)
	require.True(t, ok)
	assert.Contains(t, hosts, "./*")
	assert.Contains(t, hosts, "istio-system/*")
	assert.Contains(t, c.Tags, "sidecar")
	assert.Equal(t, gvrSidecar, c.Source)
}

func TestSidecar_Ingress(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/sidecar_ingress.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Contains(t, c.Summary, "ingress port")
	ports, ok := c.Details["ingressPorts"].([]string)
	require.True(t, ok)
	assert.Len(t, ports, 1)
	assert.Contains(t, ports[0], "8080")
}

func TestSidecar_Empty(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/sidecar_empty.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Contains(t, c.Summary, "configures sidecar proxy")
	assert.Nil(t, c.WorkloadSelector)
}

func TestSidecar_NoSelector(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/sidecar_no_selector.yaml")
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	// No workload selector = namespace-wide.
	assert.Nil(t, c.WorkloadSelector)
	assert.Contains(t, c.Summary, "restricts egress")
	hosts, ok := c.Details["egressHosts"].([]string)
	require.True(t, ok)
	assert.Len(t, hosts, 3)
}

// --- Sidecar numeric port ---

func TestSidecar_NumericPort(t *testing.T) {
	a := New()
	// Simulate how the dynamic client returns integer port numbers (float64 from JSON).
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1",
			"kind":       "Sidecar",
			"metadata": map[string]interface{}{
				"name":      "numeric-port",
				"namespace": "test-ns",
				"uid":       "numeric-port-uid",
			},
			"spec": map[string]interface{}{
				"ingress": []interface{}{
					map[string]interface{}{
						"port": map[string]interface{}{
							"number":   float64(9090),
							"protocol": "HTTP",
							"name":     "http-web",
						},
					},
				},
			},
		},
	}
	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	ports, ok := constraints[0].Details["ingressPorts"].([]string)
	require.True(t, ok)
	require.Len(t, ports, 1)
	assert.Equal(t, "9090/HTTP (http-web)", ports[0])
}

// --- Unsupported kind ---

func TestUnsupportedKind(t *testing.T) {
	a := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1",
			"kind":       "UnknownKind",
			"metadata": map[string]interface{}{
				"name": "test",
			},
		},
	}
	_, err := a.Parse(context.Background(), obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported kind")
}

// --- Input mutation check ---

func TestDoesNotMutateInput(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/authorizationpolicy_deny.yaml")
	origJSON := obj.Object
	_, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	// Verify the original object's top-level map reference is unchanged.
	assert.Equal(t, origJSON, obj.Object)
}
