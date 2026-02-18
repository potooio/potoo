//go:build integration
// +build integration

package integration

import (
	"context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/potooio/potoo/internal/adapters/kyverno"
	"github.com/potooio/potoo/internal/types"
)

// TestKyvernoAdapter_ParseClusterPolicy tests parsing a Kyverno ClusterPolicy.
func (s *KyvernoSuite) TestKyvernoAdapter_ParseClusterPolicy() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "require-labels",
				"uid":  "test-uid-kyverno-1",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Enforce",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "check-team-label",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds":      []interface{}{"Pod"},
										"namespaces": []interface{}{"production"},
									},
								},
							},
						},
						"validate": map[string]interface{}{
							"message": "Team label is required",
							"pattern": map[string]interface{}{
								"metadata": map[string]interface{}{
									"labels": map[string]interface{}{
										"team": "*",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), "require-labels/check-team-label", c.Name)
	assert.Equal(s.T(), types.SeverityCritical, c.Severity) // Enforce → Critical
	assert.Equal(s.T(), types.ConstraintTypeAdmission, c.ConstraintType)
	assert.Equal(s.T(), "deny", c.Effect)
	assert.ElementsMatch(s.T(), []string{"production"}, c.AffectedNamespaces)
	assert.Contains(s.T(), c.Tags, "kyverno")
	assert.Contains(s.T(), c.Tags, "validate")
	assert.Contains(s.T(), c.Tags, "blocking")
	assert.Contains(s.T(), c.Tags, "cluster-wide")
}

// TestKyvernoAdapter_ParsePolicy tests parsing a namespace-scoped Policy.
func (s *KyvernoSuite) TestKyvernoAdapter_ParsePolicy() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name":      "ns-policy",
				"namespace": "default",
				"uid":       "test-uid-kyverno-2",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Audit",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "audit-pods",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Pod"},
									},
								},
							},
						},
						"validate": map[string]interface{}{
							"message": "Audit message",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), "ns-policy/audit-pods", c.Name)
	assert.Equal(s.T(), "default", c.Namespace)
	assert.Equal(s.T(), types.SeverityWarning, c.Severity) // Audit → Warning
	assert.NotContains(s.T(), c.Tags, "cluster-wide")
}

// TestKyvernoAdapter_ParseMutateRule tests parsing a mutate rule.
func (s *KyvernoSuite) TestKyvernoAdapter_ParseMutateRule() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "add-defaults",
				"uid":  "test-uid-kyverno-3",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"name": "add-labels",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Pod"},
									},
								},
							},
						},
						"mutate": map[string]interface{}{
							"patchStrategicMerge": map[string]interface{}{
								"metadata": map[string]interface{}{
									"labels": map[string]interface{}{
										"managed-by": "kyverno",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), types.SeverityInfo, c.Severity) // Mutate is Info
	assert.Equal(s.T(), "mutate", c.Effect)
	assert.Contains(s.T(), c.Tags, "mutate")
}

// TestKyvernoAdapter_ParseGenerateRule tests parsing a generate rule.
func (s *KyvernoSuite) TestKyvernoAdapter_ParseGenerateRule() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "generate-netpol",
				"uid":  "test-uid-kyverno-4",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"name": "generate-default-deny",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Namespace"},
									},
								},
							},
						},
						"generate": map[string]interface{}{
							"kind":      "NetworkPolicy",
							"name":      "default-deny",
							"namespace": "{{request.object.metadata.name}}",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 1)

	c := constraints[0]
	assert.Equal(s.T(), types.SeverityInfo, c.Severity) // Generate is Info
	assert.Equal(s.T(), "generate", c.Effect)
	assert.Contains(s.T(), c.Tags, "generate")
}

// TestKyvernoAdapter_MultipleRules tests parsing a policy with multiple rules.
func (s *KyvernoSuite) TestKyvernoAdapter_MultipleRules() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "multi-rule-policy",
				"uid":  "test-uid-kyverno-5",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Enforce",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "rule-1",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Pod"},
									},
								},
							},
						},
						"validate": map[string]interface{}{
							"message": "Rule 1",
						},
					},
					map[string]interface{}{
						"name": "rule-2",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Deployment"},
									},
								},
							},
						},
						"validate": map[string]interface{}{
							"message": "Rule 2",
						},
					},
					map[string]interface{}{
						"name": "rule-3",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"StatefulSet"},
									},
								},
							},
						},
						"mutate": map[string]interface{}{},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)
	require.Len(s.T(), constraints, 3)

	// Each rule should have a unique UID
	uids := make(map[string]bool)
	for _, c := range constraints {
		assert.False(s.T(), uids[string(c.UID)], "UIDs should be unique")
		uids[string(c.UID)] = true
	}

	// Check rule names
	assert.Equal(s.T(), "multi-rule-policy/rule-1", constraints[0].Name)
	assert.Equal(s.T(), "multi-rule-policy/rule-2", constraints[1].Name)
	assert.Equal(s.T(), "multi-rule-policy/rule-3", constraints[2].Name)
}

// TestKyvernoAdapter_IndexerIntegration tests that constraints are indexed correctly.
func (s *KyvernoSuite) TestKyvernoAdapter_IndexerIntegration() {
	adapter := kyverno.New()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "indexed-policy",
				"uid":  "indexer-test-kyverno",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Enforce",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test-rule",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds":      []interface{}{"Pod"},
										"namespaces": []interface{}{"test-ns"},
									},
								},
							},
						},
						"validate": map[string]interface{}{},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), policy)
	require.NoError(s.T(), err)

	// Add to indexer
	for _, c := range constraints {
		s.idx.Upsert(c)
	}

	// Query by namespace
	results := s.idx.ByNamespace("test-ns")
	require.Len(s.T(), results, 1)

	// Query all
	allResults := s.idx.All()
	require.Len(s.T(), allResults, 1)
}

// TestKyvernoAdapter_Handles tests the GVR matching.
func (s *KyvernoSuite) TestKyvernoAdapter_Handles() {
	adapter := kyverno.New()
	gvrs := adapter.Handles()

	require.Len(s.T(), gvrs, 2)

	hasClusterPolicy := false
	hasPolicy := false
	for _, gvr := range gvrs {
		assert.Equal(s.T(), "kyverno.io", gvr.Group)
		assert.Equal(s.T(), "v1", gvr.Version)
		if gvr.Resource == "clusterpolicies" {
			hasClusterPolicy = true
		}
		if gvr.Resource == "policies" {
			hasPolicy = true
		}
	}
	assert.True(s.T(), hasClusterPolicy)
	assert.True(s.T(), hasPolicy)
}
