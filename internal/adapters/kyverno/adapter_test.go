package kyverno

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
	assert.Equal(t, "kyverno", adapter.Name())
}

func TestAdapter_Handles(t *testing.T) {
	adapter := New()
	gvrs := adapter.Handles()

	require.Len(t, gvrs, 2)

	// Check ClusterPolicy GVR
	hasClusterPolicy := false
	hasPolicy := false
	for _, gvr := range gvrs {
		if gvr.Resource == "clusterpolicies" {
			hasClusterPolicy = true
			assert.Equal(t, "kyverno.io", gvr.Group)
			assert.Equal(t, "v1", gvr.Version)
		}
		if gvr.Resource == "policies" {
			hasPolicy = true
			assert.Equal(t, "kyverno.io", gvr.Group)
			assert.Equal(t, "v1", gvr.Version)
		}
	}
	assert.True(t, hasClusterPolicy, "should handle clusterpolicies")
	assert.True(t, hasPolicy, "should handle policies")
}

func TestAdapter_Parse_ClusterPolicyValidate(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "clusterpolicy_validate.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)

	// Should have 2 constraints (one per rule)
	require.Len(t, constraints, 2)

	// First rule: check-team-label
	c1 := constraints[0]
	assert.Equal(t, "require-labels/check-team-label", c1.Name)
	assert.Empty(t, c1.Namespace)                        // ClusterPolicy is cluster-scoped
	assert.Equal(t, types.SeverityCritical, c1.Severity) // Enforce → Critical
	assert.Equal(t, "deny", c1.Effect)
	assert.Equal(t, types.ConstraintTypeAdmission, c1.ConstraintType)

	// Affected namespaces
	assert.ElementsMatch(t, []string{"production", "staging"}, c1.AffectedNamespaces)

	// Resource targets
	require.NotEmpty(t, c1.ResourceTargets)
	assert.Contains(t, c1.ResourceTargets[0].Resources, "pods")

	// Workload selector
	require.NotNil(t, c1.WorkloadSelector)
	assert.Equal(t, "helm", c1.WorkloadSelector.MatchLabels["app.kubernetes.io/managed-by"])

	// Summary
	assert.Contains(t, c1.Summary, "ClusterPolicy")
	assert.Contains(t, c1.Summary, "require-labels")
	assert.Contains(t, c1.Summary, "check-team-label")
	assert.Contains(t, c1.Summary, "enforces")

	// Tags
	assert.Contains(t, c1.Tags, "kyverno")
	assert.Contains(t, c1.Tags, "validate")
	assert.Contains(t, c1.Tags, "blocking")
	assert.Contains(t, c1.Tags, "cluster-wide")

	// Details
	assert.Equal(t, "validate", c1.Details["ruleType"])
	assert.NotEmpty(t, c1.Details["validationMessage"])

	// Second rule: check-env-label
	c2 := constraints[1]
	assert.Equal(t, "require-labels/check-env-label", c2.Name)
	assert.Contains(t, c2.ResourceTargets[0].Resources, "deployments")
}

func TestAdapter_Parse_PolicyMutate(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "policy_mutate.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]

	// Identity
	assert.Equal(t, "add-default-resources/add-cpu-limits", c.Name)
	assert.Equal(t, "default", c.Namespace)

	// Mutate rules are Info severity
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "mutate", c.Effect)

	// Summary
	assert.Contains(t, c.Summary, "Policy")
	assert.Contains(t, c.Summary, "mutates")

	// Tags
	assert.Contains(t, c.Tags, "mutate")
	assert.NotContains(t, c.Tags, "cluster-wide")

	// Details
	assert.Equal(t, "mutate", c.Details["ruleType"])
}

func TestAdapter_Parse_GenerateRule(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "generate_rule.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]

	// Generate rules are Info severity
	assert.Equal(t, types.SeverityInfo, c.Severity)
	assert.Equal(t, "generate", c.Effect)

	// Summary
	assert.Contains(t, c.Summary, "generates resources from")

	// Tags
	assert.Contains(t, c.Tags, "generate")
}

func TestAdapter_Parse_MissingSpec(t *testing.T) {
	adapter := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "test",
			},
		},
	}

	_, err := adapter.Parse(context.Background(), obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing spec")
}

func TestAdapter_Parse_NoRules(t *testing.T) {
	adapter := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "test",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{},
			},
		},
	}

	_, err := adapter.Parse(context.Background(), obj)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestAdapter_Parse_DefaultValidationAction(t *testing.T) {
	adapter := New()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "test",
				"uid":  "test-uid",
			},
			"spec": map[string]interface{}{
				// No validationFailureAction - should default to Audit
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test-rule",
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
							"message": "test",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	// Default should be Audit → Warning
	assert.Equal(t, types.SeverityWarning, constraints[0].Severity)
}

func TestAdapter_Parse_UniqueRuleUIDs(t *testing.T) {
	adapter := New()
	obj := loadTestData(t, "clusterpolicy_validate.yaml")

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 2)

	// Each rule should have a unique UID
	assert.NotEqual(t, constraints[0].UID, constraints[1].UID)
	assert.Contains(t, string(constraints[0].UID), "rule-0")
	assert.Contains(t, string(constraints[1].UID), "rule-1")
}

func TestMapValidationActionToSeverity(t *testing.T) {
	tests := []struct {
		action   string
		expected types.Severity
	}{
		{"Enforce", types.SeverityCritical},
		{"enforce", types.SeverityCritical},
		{"ENFORCE", types.SeverityCritical},
		{"Audit", types.SeverityWarning},
		{"audit", types.SeverityWarning},
		{"unknown", types.SeverityWarning},
		{"", types.SeverityWarning},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapValidationActionToSeverity(tc.action))
		})
	}
}

func TestDetermineRuleType(t *testing.T) {
	tests := []struct {
		name         string
		rule         map[string]interface{}
		expectedType string
		expectedEff  string
	}{
		{
			name:         "validate rule",
			rule:         map[string]interface{}{"validate": map[string]interface{}{}},
			expectedType: "validate",
			expectedEff:  "deny",
		},
		{
			name:         "mutate rule",
			rule:         map[string]interface{}{"mutate": map[string]interface{}{}},
			expectedType: "mutate",
			expectedEff:  "mutate",
		},
		{
			name:         "generate rule",
			rule:         map[string]interface{}{"generate": map[string]interface{}{}},
			expectedType: "generate",
			expectedEff:  "generate",
		},
		{
			name:         "verifyImages rule (map)",
			rule:         map[string]interface{}{"verifyImages": map[string]interface{}{}},
			expectedType: "verifyImages",
			expectedEff:  "deny",
		},
		{
			name:         "verifyImages rule (slice)",
			rule:         map[string]interface{}{"verifyImages": []interface{}{}},
			expectedType: "verifyImages",
			expectedEff:  "deny",
		},
		{
			name:         "unknown rule",
			rule:         map[string]interface{}{"something": map[string]interface{}{}},
			expectedType: "unknown",
			expectedEff:  "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ruleType, effect := determineRuleType(tc.rule)
			assert.Equal(t, tc.expectedType, ruleType)
			assert.Equal(t, tc.expectedEff, effect)
		})
	}
}

func TestMapRuleTypeToConstraintType(t *testing.T) {
	tests := []struct {
		ruleType     string
		expectedType types.ConstraintType
	}{
		{"validate", types.ConstraintTypeAdmission},
		{"verifyImages", types.ConstraintTypeAdmission},
		{"mutate", types.ConstraintTypeAdmission},
		{"generate", types.ConstraintTypeAdmission},
		{"unknown", types.ConstraintTypeUnknown},
		{"somethingelse", types.ConstraintTypeUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.ruleType, func(t *testing.T) {
			assert.Equal(t, tc.expectedType, mapRuleTypeToConstraintType(tc.ruleType))
		})
	}
}

func TestAdapter_Parse_MatchAllClause(t *testing.T) {
	adapter := New()

	// Policy using match.all instead of match.any
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "match-all-policy",
				"uid":  "uid-match-all",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Enforce",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "require-annotation",
						"match": map[string]interface{}{
							"all": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds":      []interface{}{"Deployment"},
										"namespaces": []interface{}{"production"},
										"selector": map[string]interface{}{
											"matchLabels": map[string]interface{}{
												"tier": "frontend",
											},
										},
									},
								},
							},
						},
						"validate": map[string]interface{}{
							"message": "Annotation team is required",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, "match-all-policy/require-annotation", c.Name)
	assert.Equal(t, types.SeverityCritical, c.Severity)
	assert.ElementsMatch(t, []string{"production"}, c.AffectedNamespaces)
	require.NotNil(t, c.WorkloadSelector)
	assert.Equal(t, "frontend", c.WorkloadSelector.MatchLabels["tier"])
	require.NotEmpty(t, c.ResourceTargets)
	assert.Contains(t, c.ResourceTargets[0].Resources, "deployments")
}

func TestAdapter_Parse_LegacyMatchResources(t *testing.T) {
	adapter := New()

	// Policy using legacy match.resources (directly on match, not inside any/all)
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "legacy-match-policy",
				"uid":  "uid-legacy-match",
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Audit",
				"rules": []interface{}{
					map[string]interface{}{
						"name": "check-labels",
						"match": map[string]interface{}{
							"resources": map[string]interface{}{
								"kinds":      []interface{}{"Pod", "apps/Deployment"},
								"namespaces": []interface{}{"staging", "production"},
							},
						},
						"validate": map[string]interface{}{
							"message": "Labels are required",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.SeverityWarning, c.Severity)
	assert.ElementsMatch(t, []string{"staging", "production"}, c.AffectedNamespaces)
	require.NotEmpty(t, c.ResourceTargets)
	// "Pod" becomes "pods", "apps/Deployment" becomes apiGroup=apps, resource=deployments
	assert.Contains(t, c.ResourceTargets[0].Resources, "pods")
	assert.Contains(t, c.ResourceTargets[0].Resources, "deployments")
	assert.Contains(t, c.ResourceTargets[0].APIGroups, "apps")
}

func TestAdapter_Parse_UnknownRuleType(t *testing.T) {
	adapter := New()

	// Policy with an unrecognized rule type should fail with "no valid rules parsed"
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": "bad-rule-type-policy",
				"uid":  "uid-bad-rule",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"name": "weird-rule",
						"match": map[string]interface{}{
							"any": []interface{}{
								map[string]interface{}{
									"resources": map[string]interface{}{
										"kinds": []interface{}{"Pod"},
									},
								},
							},
						},
						"customAction": map[string]interface{}{
							"something": "else",
						},
					},
				},
			},
		},
	}

	constraints, err := adapter.Parse(context.Background(), obj)
	require.NoError(t, err)
	require.Len(t, constraints, 1)

	c := constraints[0]
	assert.Equal(t, types.ConstraintTypeUnknown, c.ConstraintType)
	assert.Equal(t, "unknown", c.Effect)
}
