package limitrange

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
	assert.Equal(t, "limitrange", a.Name())
}

func TestHandles(t *testing.T) {
	a := New()
	gvrs := a.Handles()
	require.Len(t, gvrs, 1)
	assert.Equal(t, "", gvrs[0].Group)
	assert.Equal(t, "v1", gvrs[0].Version)
	assert.Equal(t, "limitranges", gvrs[0].Resource)
}

func TestParse_ContainerLimits(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/container_limits.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeResourceLimit, c.ConstraintType)
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "team-alpha", c.Namespace)
	assert.Equal(t, []string{"team-alpha"}, c.AffectedNamespaces)
	assert.Contains(t, c.Summary, "Container")

	// Check details
	details := c.Details
	assert.Equal(t, "Container", details["type"])
	assert.NotNil(t, details["default"])
	assert.NotNil(t, details["max"])
	assert.NotNil(t, details["min"])
}

func TestParse_MultipleTypes(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/multiple_types.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 2, "should produce 2 constraints for 2 limit entries")

	typeSet := map[string]bool{}
	for _, c := range constraints {
		assert.Equal(t, types.ConstraintTypeResourceLimit, c.ConstraintType)
		assert.Equal(t, types.SeverityInfo, c.Severity)
		typeSet[c.Details["type"].(string)] = true
	}
	assert.True(t, typeSet["Container"], "should have Container constraint")
	assert.True(t, typeSet["Pod"], "should have Pod constraint")
}

func TestParse_DoesNotMutateInput(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/container_limits.yaml")
	before := obj.DeepCopy()

	_, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	assert.Equal(t, before.Object, obj.Object, "Parse() must not mutate the input object")
}
