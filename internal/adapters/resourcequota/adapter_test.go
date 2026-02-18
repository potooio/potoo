package resourcequota

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
	assert.Equal(t, "resourcequota", a.Name())
}

func TestHandles(t *testing.T) {
	a := New()
	gvrs := a.Handles()
	require.Len(t, gvrs, 1)
	assert.Equal(t, "", gvrs[0].Group)
	assert.Equal(t, "v1", gvrs[0].Version)
	assert.Equal(t, "resourcequotas", gvrs[0].Resource)
}

func TestParse_NearLimit(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/near_limit.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeResourceLimit, c.ConstraintType)
	assert.Equal(t, types.SeverityWarning, c.Severity, "80% CPU usage should be Warning")
	assert.Equal(t, "team-alpha-quota", c.Name)
	assert.Equal(t, "team-alpha", c.Namespace)
	assert.Equal(t, []string{"team-alpha"}, c.AffectedNamespaces)
	assert.Contains(t, c.Summary, "CPU")
	assert.Contains(t, c.Summary, "Memory")
}

func TestParse_CriticalUsage(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/critical_usage.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityCritical, c.Severity, "95% CPU usage should be Critical")
}

func TestParse_LowUsage(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/low_usage.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityInfo, c.Severity, "25% CPU usage should be Info")
}

func TestParse_DoesNotMutateInput(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/near_limit.yaml")
	before := obj.DeepCopy()

	_, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	assert.Equal(t, before.Object, obj.Object, "Parse() must not mutate the input object")
}
