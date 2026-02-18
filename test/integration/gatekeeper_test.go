//go:build integration
// +build integration

package integration

import (
	"context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/adapters/gatekeeper"
	"github.com/potooio/potoo/internal/types"
)

// TestGatekeeperAdapter_ParseConstraint tests parsing a Gatekeeper constraint.
func (s *GatekeeperSuite) TestGatekeeperAdapter_ParseConstraint() {
	adapter := gatekeeper.New()

	// Create a K8sRequiredLabels constraint
	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sRequiredLabels",
			"metadata": map[string]interface{}{
				"name": "require-team-label",
				"uid":  "test-uid-123",
			},
			"spec": map[string]interface{}{
				"enforcementAction": "deny",
				"match": map[string]interface{}{
					"kinds": []interface{}{
						map[string]interface{}{
							"apiGroups": []interface{}{""},
							"kinds":     []interface{}{"Pod"},
						},
					},
					"namespaces": []interface{}{"production", "staging"},
				},
				"parameters": map[string]interface{}{
					"labels": []interface{}{"team"},
				},
			},
		},
	}

	// Parse the constraint
	constraints, err := adapter.Parse(context.Background(), constraint)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), "require-team-label", c.Name)
	assert.Equal(s.T(), types.SeverityCritical, c.Severity)
	assert.Equal(s.T(), types.ConstraintTypeAdmission, c.ConstraintType)
	assert.Equal(s.T(), "deny", c.Effect)
	assert.ElementsMatch(s.T(), []string{"production", "staging"}, c.AffectedNamespaces)
	assert.Contains(s.T(), c.Tags, "gatekeeper")
	assert.Contains(s.T(), c.Tags, "blocking")
}

// TestGatekeeperAdapter_ParseWarnConstraint tests parsing a warn-mode constraint.
func (s *GatekeeperSuite) TestGatekeeperAdapter_ParseWarnConstraint() {
	adapter := gatekeeper.New()

	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sUniqueIngressHost",
			"metadata": map[string]interface{}{
				"name": "unique-ingress",
				"uid":  "test-uid-456",
			},
			"spec": map[string]interface{}{
				"enforcementAction": "warn",
				"match": map[string]interface{}{
					"kinds": []interface{}{
						map[string]interface{}{
							"apiGroups": []interface{}{"networking.k8s.io"},
							"kinds":     []interface{}{"Ingress"},
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), constraint)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), types.SeverityWarning, c.Severity)
	assert.Equal(s.T(), "warn", c.Effect)
	assert.Contains(s.T(), c.Tags, "warning")
}

// TestGatekeeperAdapter_ParseDryrunConstraint tests parsing a dryrun-mode constraint.
func (s *GatekeeperSuite) TestGatekeeperAdapter_ParseDryrunConstraint() {
	adapter := gatekeeper.New()

	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sDenyAll",
			"metadata": map[string]interface{}{
				"name": "audit-all",
				"uid":  "test-uid-789",
			},
			"spec": map[string]interface{}{
				"enforcementAction": "dryrun",
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), constraint)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), types.SeverityInfo, c.Severity)
	assert.Equal(s.T(), "audit", c.Effect)
	assert.Contains(s.T(), c.Tags, "audit")
}

// TestGatekeeperAdapter_Handles tests the GVR matching.
func (s *GatekeeperSuite) TestGatekeeperAdapter_Handles() {
	adapter := gatekeeper.New()
	gvrs := adapter.Handles()

	require.Len(s.T(), gvrs, 1)
	assert.Equal(s.T(), gatekeeper.GatekeeperConstraintGroup, gvrs[0].Group)
	assert.Equal(s.T(), "*", gvrs[0].Resource, "should use wildcard for dynamic CRDs")
}

// TestGatekeeperAdapter_IndexerIntegration tests that constraints are indexed correctly.
func (s *GatekeeperSuite) TestGatekeeperAdapter_IndexerIntegration() {
	adapter := gatekeeper.New()

	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       "K8sRequiredLabels",
			"metadata": map[string]interface{}{
				"name": "indexed-constraint",
				"uid":  "indexer-test-uid",
			},
			"spec": map[string]interface{}{
				"enforcementAction": "deny",
				"match": map[string]interface{}{
					"namespaces": []interface{}{"default"},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), constraint)
	require.NoError(s.T(), err)

	// Add to indexer
	for _, c := range constraints {
		s.idx.Upsert(c)
	}

	// Query by namespace
	results := s.idx.ByNamespace("default")
	require.Len(s.T(), results, 1)
	assert.Equal(s.T(), "indexed-constraint", results[0].Name)

	// Query by type
	typeResults := s.idx.ByType(types.ConstraintTypeAdmission)
	require.Len(s.T(), typeResults, 1)
}

// TestGatekeeperAdapter_RegistryGroupLookup tests ForGroup registry lookup.
func (s *GatekeeperSuite) TestGatekeeperAdapter_RegistryGroupLookup() {
	// Adapter should be registered
	adapter := s.registry.ForGroup(gatekeeper.GatekeeperConstraintGroup)
	require.NotNil(s.T(), adapter)
	assert.Equal(s.T(), "gatekeeper", adapter.Name())

	// Random GVR in the group should find the adapter
	randomGVR := schema.GroupVersionResource{
		Group:    gatekeeper.GatekeeperConstraintGroup,
		Version:  "v1beta1",
		Resource: "k8ssomecustomconstraint",
	}
	adapter = s.registry.ForGroup(randomGVR.Group)
	require.NotNil(s.T(), adapter)
	assert.Equal(s.T(), "gatekeeper", adapter.Name())
}
