package webhookconfig

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
	assert.Equal(t, "webhookconfig", a.Name())
}

func TestHandles(t *testing.T) {
	a := New()
	gvrs := a.Handles()
	require.Len(t, gvrs, 2)

	gvrSet := make(map[string]bool)
	for _, gvr := range gvrs {
		gvrSet[gvr.Resource] = true
	}
	assert.True(t, gvrSet["validatingwebhookconfigurations"])
	assert.True(t, gvrSet["mutatingwebhookconfigurations"])
}

func TestParse_ValidatingWebhook(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/validating_webhook.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeAdmission, c.ConstraintType)
	assert.Equal(t, types.SeverityWarning, c.Severity, "failurePolicy=Fail should be Warning")
	assert.Contains(t, c.Summary, "Validating webhook")
	assert.Equal(t, "", c.Namespace, "webhook configs are cluster-scoped")

	// Check details
	assert.Equal(t, "Fail", c.Details["failurePolicy"])
	assert.Equal(t, "Validating", c.Details["webhookType"])
}

func TestParse_MutatingWebhook(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/mutating_webhook.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeAdmission, c.ConstraintType)
	assert.Equal(t, types.SeverityInfo, c.Severity, "failurePolicy=Ignore should be Info")
	assert.Contains(t, c.Summary, "Mutating webhook")

	assert.Equal(t, "Ignore", c.Details["failurePolicy"])
	assert.Equal(t, "Mutating", c.Details["webhookType"])
}

func TestParse_SkipsPotooWebhooks(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/potoo_webhook.yaml")

	constraints, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	assert.Len(t, constraints, 0, "potoo webhooks should be skipped")
}

func TestParse_DoesNotMutateInput(t *testing.T) {
	a := New()
	obj := loadFixture(t, "testdata/validating_webhook.yaml")
	before := obj.DeepCopy()

	_, err := a.Parse(context.Background(), obj)
	require.NoError(t, err)
	assert.Equal(t, before.Object, obj.Object, "Parse() must not mutate the input object")
}
