package networkpolicy

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
	assert.Equal(t, "networkpolicy", a.Name())
}

func TestHandles(t *testing.T) {
	a := New()
	gvrs := a.Handles()
	require.Len(t, gvrs, 1)
	assert.Equal(t, "networking.k8s.io", gvrs[0].Group)
	assert.Equal(t, "v1", gvrs[0].Version)
	assert.Equal(t, "networkpolicies", gvrs[0].Resource)
}

func TestParse_DefaultDenyIngress(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/default_deny_ingress.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1, "default-deny-ingress should produce 1 constraint (ingress only)")

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeNetworkIngress, c.ConstraintType)
	assert.Equal(t, "default-deny-ingress", c.Name)
	assert.Equal(t, "team-alpha", c.Namespace)
	assert.Contains(t, c.Summary, "denies all ingress")
	assert.Equal(t, []string{"team-alpha"}, c.AffectedNamespaces)
}

func TestParse_EgressRestrict(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/egress_restrict.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1, "egress-only policy should produce 1 constraint")

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeNetworkEgress, c.ConstraintType)
	assert.Equal(t, "restrict-egress", c.Name)
	assert.Equal(t, "team-alpha", c.Namespace)

	// WorkloadSelector should match app=api-server
	require.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "api-server", c.WorkloadSelector.MatchLabels["app"])

	// Summary should mention the policy restricts egress
	assert.Contains(t, c.Summary, "egress")
}

func TestParse_IngressAndEgress(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/ingress_and_egress.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 2, "policy with both Ingress and Egress policyTypes should produce 2 constraints")

	typeSet := map[types.ConstraintType]bool{}
	for _, c := range constraints {
		typeSet[c.ConstraintType] = true
	}
	assert.True(t, typeSet[types.ConstraintTypeNetworkIngress], "should have ingress constraint")
	assert.True(t, typeSet[types.ConstraintTypeNetworkEgress], "should have egress constraint")
}

func TestParse_DefaultDenyEgress(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/default_deny_egress.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeNetworkEgress, c.ConstraintType)
	assert.Contains(t, c.Summary, "denies all egress")
}

func TestParse_DoesNotMutateInput(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/egress_restrict.yaml")

	// Deep copy the raw JSON to compare later
	before := obj.DeepCopy()

	_, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)

	// The input object must not have been modified
	assert.Equal(t, before.Object, obj.Object, "Parse() must not mutate the input object")
}
