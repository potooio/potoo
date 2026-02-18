// Package testutil provides shared test helpers for the potoo project.
// Import this in test files to avoid duplicating fixture loading, constraint builders, etc.
package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/potooio/potoo/internal/types"
)

// LoadFixture reads a YAML file and returns it as an Unstructured object.
// Fails the test immediately if the file can't be read or parsed.
func LoadFixture(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture %s", path)
	obj := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal(data, &obj.Object), "failed to parse fixture %s", path)
	return obj
}

// MakeConstraint creates a test Constraint with the given parameters.
// Use for building test data in indexer, correlator, and notifier tests.
func MakeConstraint(uid string, ns string, ct types.ConstraintType, selectorLabels map[string]string) types.Constraint {
	var selector *metav1.LabelSelector
	if selectorLabels != nil {
		selector = &metav1.LabelSelector{MatchLabels: selectorLabels}
	}
	return types.Constraint{
		UID:                k8stypes.UID(uid),
		Name:               "test-" + uid,
		Namespace:          ns,
		AffectedNamespaces: []string{ns},
		WorkloadSelector:   selector,
		ConstraintType:     ct,
		Severity:           types.SeverityWarning,
		Effect:             "restrict",
		Summary:            "Test constraint " + uid,
		Source:             schema.GroupVersionResource{Group: "test", Version: "v1", Resource: "tests"},
	}
}
