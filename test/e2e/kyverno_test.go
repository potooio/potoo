//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the Kyverno adapter.
// These tests require Kyverno to be installed in the cluster
// (via make e2e-setup or make e2e-setup-dd). Tests skip gracefully
// if Kyverno CRDs are absent.
package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"

	"github.com/potooio/potoo/internal/annotations"
)

// Kyverno GVRs.
var (
	clusterPolicyGVR = schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}
	kyvernoPolicyGVR = schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "policies",
	}
)

const (
	// kyvernoAnnotationTimeout accounts for: CRD rescan (30s) + informer sync +
	// adapter parse + indexer upsert + debounce (30s) + annotator patch.
	// Use 180s to accommodate parallel test contention on single-node clusters
	// (e.g. Docker Desktop) where all 7 test groups compete for controller cycles.
	kyvernoAnnotationTimeout = 180 * time.Second
)

// requireKyvernoInstalled skips the test if Kyverno CRDs are not installed.
func requireKyvernoInstalled(t *testing.T, dynamicClient dynamic.Interface) {
	t.Helper()
	_, err := dynamicClient.Resource(crdGVR).Get(
		context.Background(), "clusterpolicies.kyverno.io", metav1.GetOptions{},
	)
	if err != nil {
		t.Skip("Skipping: Kyverno CRDs not installed (clusterpolicies.kyverno.io not found)")
	}
}

// createKyvernoClusterPolicy creates a Kyverno ClusterPolicy with the given
// validationFailureAction and rules. Returns a cleanup function.
func createKyvernoClusterPolicy(
	t *testing.T,
	dynamicClient dynamic.Interface,
	name, validationFailureAction string,
	rules []interface{},
) func() {
	t.Helper()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": map[string]interface{}{
				"validationFailureAction": validationFailureAction,
				"background":              false,
				"rules":                   rules,
			},
		},
	}

	_, err := dynamicClient.Resource(clusterPolicyGVR).Create(
		context.Background(), policy, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create ClusterPolicy %s", name)
	t.Logf("Created Kyverno ClusterPolicy: %s (validationFailureAction=%s, rules=%d)", name, validationFailureAction, len(rules))

	return func() {
		deleteUnstructured(t, dynamicClient, clusterPolicyGVR, "", name)
	}
}

// createKyvernoPolicy creates a namespace-scoped Kyverno Policy. Returns a cleanup function.
func createKyvernoPolicy(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, name string,
	rules []interface{},
) func() {
	t.Helper()

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kyverno.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"validationFailureAction": "Audit",
				"background":              false,
				"rules":                   rules,
			},
		},
	}

	_, err := dynamicClient.Resource(kyvernoPolicyGVR).Namespace(namespace).Create(
		context.Background(), policy, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create Policy %s/%s", namespace, name)
	t.Logf("Created Kyverno Policy: %s/%s (rules=%d)", namespace, name, len(rules))

	return func() {
		deleteUnstructured(t, dynamicClient, kyvernoPolicyGVR, namespace, name)
	}
}

// kyvernoValidateRule builds a Kyverno validate rule map.
func kyvernoValidateRule(name string, matchAny []interface{}, message string) map[string]interface{} {
	rule := map[string]interface{}{
		"name": name,
		"validate": map[string]interface{}{
			"message": message,
			"pattern": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"team": "?*",
					},
				},
			},
		},
	}
	if len(matchAny) > 0 {
		rule["match"] = map[string]interface{}{
			"any": matchAny,
		}
	}
	return rule
}

// kyvernoMutateRule builds a Kyverno mutate rule map.
func kyvernoMutateRule(name string, matchAny []interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"name": name,
		"mutate": map[string]interface{}{
			"patchStrategicMerge": map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"mutated-by": "kyverno",
					},
				},
			},
		},
	}
	if len(matchAny) > 0 {
		rule["match"] = map[string]interface{}{
			"any": matchAny,
		}
	}
	return rule
}

// kyvernoGenerateRule builds a Kyverno generate rule map.
func kyvernoGenerateRule(name string, matchAny []interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"name": name,
		"generate": map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"name":       "generated-cm",
			"namespace":  "{{request.namespace}}",
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"generated": "true",
				},
			},
		},
	}
	if len(matchAny) > 0 {
		rule["match"] = map[string]interface{}{
			"any": matchAny,
		}
	}
	return rule
}

// kyvernoMatchAnyPods returns a match.any clause targeting Pods.
func kyvernoMatchAnyPods() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"resources": map[string]interface{}{
				"kinds": []interface{}{"Pod"},
			},
		},
	}
}

// kyvernoMatchAnyKindsNamespaces returns a match.any clause targeting specific
// kinds in specific namespaces.
func kyvernoMatchAnyKindsNamespaces(kinds []string, namespaces []string) []interface{} {
	kindsList := make([]interface{}, len(kinds))
	for i, k := range kinds {
		kindsList[i] = k
	}
	nsList := make([]interface{}, len(namespaces))
	for i, ns := range namespaces {
		nsList[i] = ns
	}
	return []interface{}{
		map[string]interface{}{
			"resources": map[string]interface{}{
				"kinds":      kindsList,
				"namespaces": nsList,
			},
		},
	}
}

// TestKyverno runs all Kyverno adapter E2E tests.
func TestKyverno(t *testing.T) {
	t.Parallel()

	// ClusterPolicyDiscovery verifies that creating a Kyverno ClusterPolicy
	// with an Enforce validate rule causes it to be discovered, indexed as Critical
	// severity, and annotated on workloads.
	t.Run("ClusterPolicyDiscovery", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-kv-disc-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		policyName := "e2e-kv-enforce-" + rand.String(5)
		cleanupPolicy := createKyvernoClusterPolicy(
			t, sharedDynamicClient,
			policyName, "Enforce",
			[]interface{}{
				kyvernoValidateRule("check-labels", kyvernoMatchAnyKindsNamespaces([]string{"Pod"}, []string{ns}), "Must have team label"),
			},
		)
		t.Cleanup(cleanupPolicy)

		// ClusterPolicies are cluster-scoped — trigger the annotator for this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-disc")
		t.Cleanup(cleanupTrigger)

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, policyName)
		})
		require.NotEmpty(t, constraints, "expected Admission constraint containing %q", policyName)

		for _, c := range constraints {
			if c.Type == "Admission" && strings.Contains(c.Name, policyName) {
				assert.Equal(t, "Critical", c.Severity, "Enforce should map to Critical severity")
				assert.Equal(t, "clusterpolicies", c.Source, "source should be clusterpolicies")
				t.Logf("Found Kyverno constraint: type=%s name=%s source=%s severity=%s", c.Type, c.Name, c.Source, c.Severity)
				break
			}
		}
	})

	// NamespacePolicyDiscovery verifies that a namespace-scoped Kyverno
	// Policy with an Audit validate rule is discovered as Warning severity and
	// scoped to the policy's namespace.
	t.Run("NamespacePolicyDiscovery", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-kv-ns-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		policyName := "e2e-kv-audit-" + rand.String(5)
		cleanupPolicy := createKyvernoPolicy(
			t, sharedDynamicClient,
			ns, policyName,
			[]interface{}{
				kyvernoValidateRule("check-labels", kyvernoMatchAnyPods(), "Should have team label"),
			},
		)
		t.Cleanup(cleanupPolicy)

		// Namespace-scoped policies should trigger annotator via indexer onChange,
		// but add a trigger for reliability under CI timing.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-ns")
		t.Cleanup(cleanupTrigger)

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, policyName)
		})
		require.NotEmpty(t, constraints, "expected Admission constraint containing %q in namespace %s", policyName, ns)

		for _, c := range constraints {
			if c.Type == "Admission" && strings.Contains(c.Name, policyName) {
				assert.Equal(t, "Warning", c.Severity, "Audit should map to Warning severity")
				assert.Equal(t, "policies", c.Source, "source should be policies for namespace-scoped")
				t.Logf("Found Kyverno ns-policy constraint: type=%s name=%s source=%s severity=%s", c.Type, c.Name, c.Source, c.Severity)
				break
			}
		}
	})

	// MultiRulePolicy verifies that a ClusterPolicy with multiple rules
	// produces a separate constraint per rule, each with a unique name in the format
	// "policyName/ruleName".
	t.Run("MultiRulePolicy", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-kv-multi-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		policyName := "e2e-kv-multi-" + rand.String(5)
		matchNS := kyvernoMatchAnyKindsNamespaces([]string{"Pod"}, []string{ns})
		cleanupPolicy := createKyvernoClusterPolicy(
			t, sharedDynamicClient,
			policyName, "Enforce",
			[]interface{}{
				kyvernoValidateRule("check-team-label", matchNS, "Must have team label"),
				kyvernoValidateRule("check-env-label", matchNS, "Must have env label"),
			},
		)
		t.Cleanup(cleanupPolicy)

		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-multi")
		t.Cleanup(cleanupTrigger)

		// Wait for the first rule constraint.
		rule1Name := policyName + "/check-team-label"
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, rule1Name)
		})
		require.NotEmpty(t, constraints, "expected constraint for rule %q", rule1Name)

		// Wait for the second rule constraint.
		rule2Name := policyName + "/check-env-label"
		constraints = waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, rule2Name)
		})
		require.NotEmpty(t, constraints, "expected constraint for rule %q", rule2Name)

		// Verify both rules appear as distinct constraints.
		foundRule1 := false
		foundRule2 := false
		for _, c := range constraints {
			if c.Type == "Admission" && strings.Contains(c.Name, rule1Name) {
				foundRule1 = true
				t.Logf("Found multi-rule constraint 1: name=%s severity=%s", c.Name, c.Severity)
			}
			if c.Type == "Admission" && strings.Contains(c.Name, rule2Name) {
				foundRule2 = true
				t.Logf("Found multi-rule constraint 2: name=%s severity=%s", c.Name, c.Severity)
			}
		}
		assert.True(t, foundRule1, "first rule constraint %q should be present", rule1Name)
		assert.True(t, foundRule2, "second rule constraint %q should be present", rule2Name)
	})

	// MutateGenerateSeverity verifies that mutate and generate rules
	// are indexed as Info severity.
	t.Run("MutateGenerateSeverity", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		tests := []struct {
			name     string
			ruleType string
			rule     map[string]interface{}
		}{
			{
				name:     "mutate",
				ruleType: "mutate",
				rule:     kyvernoMutateRule("add-label", kyvernoMatchAnyPods()),
			},
			{
				name:     "generate",
				ruleType: "generate",
				rule:     kyvernoGenerateRule("gen-configmap", kyvernoMatchAnyPods()),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ns, cleanupNS := createTestNamespace(t, sharedClientset)
				t.Cleanup(cleanupNS)

				sentinelName := "sentinel-kv-" + tt.name + "-" + rand.String(5)
				cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
				t.Cleanup(cleanup)
				waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

				policyName := fmt.Sprintf("e2e-kv-%s-%s", tt.name, rand.String(5))
				// Mutate/generate rules don't use validationFailureAction;
				// set to Audit (default) — severity comes from rule type, not action.
				cleanupPolicy := createKyvernoClusterPolicy(
					t, sharedDynamicClient,
					policyName, "Audit",
					[]interface{}{tt.rule},
				)
				t.Cleanup(cleanupPolicy)

				cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-"+tt.name)
				t.Cleanup(cleanupTrigger)

				constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
					return c.Type == "Admission" && strings.Contains(c.Name, policyName)
				})
				require.NotEmpty(t, constraints, "expected constraint for %s policy %q", tt.name, policyName)

				for _, c := range constraints {
					if c.Type == "Admission" && strings.Contains(c.Name, policyName) {
						assert.Equal(t, "Info", c.Severity,
							"%s rule should map to Info severity", tt.ruleType)
						t.Logf("Verified: %s rule → severity=%s (name=%s)", tt.ruleType, c.Severity, c.Name)
						break
					}
				}
			})
		}
	})

	// EnforcementMapping verifies that Kyverno validationFailureAction
	// maps to the correct Potoo severity levels:
	//
	//	Enforce → Critical
	//	Audit   → Warning
	t.Run("EnforcementMapping", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		tests := []struct {
			action   string
			severity string
		}{
			{"Enforce", "Critical"},
			{"Audit", "Warning"},
		}

		for _, tt := range tests {
			t.Run(tt.action, func(t *testing.T) {
				ns, cleanupNS := createTestNamespace(t, sharedClientset)
				t.Cleanup(cleanupNS)

				sentinelName := "sentinel-kv-" + strings.ToLower(tt.action) + "-" + rand.String(5)
				cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
				t.Cleanup(cleanup)
				waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

				policyName := fmt.Sprintf("e2e-kv-%s-%s", strings.ToLower(tt.action), rand.String(5))
				cleanupPolicy := createKyvernoClusterPolicy(
					t, sharedDynamicClient,
					policyName, tt.action,
					[]interface{}{
						kyvernoValidateRule("check-labels", kyvernoMatchAnyKindsNamespaces([]string{"Pod"}, []string{ns}), "Must have team label"),
					},
				)
				t.Cleanup(cleanupPolicy)

				cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-"+strings.ToLower(tt.action))
				t.Cleanup(cleanupTrigger)

				constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
					return c.Type == "Admission" && strings.Contains(c.Name, policyName)
				})
				require.NotEmpty(t, constraints, "expected constraint %q for action=%s", policyName, tt.action)

				for _, c := range constraints {
					if c.Type == "Admission" && strings.Contains(c.Name, policyName) {
						assert.Equal(t, tt.severity, c.Severity,
							"validationFailureAction=%s should map to severity=%s", tt.action, tt.severity)
						t.Logf("Verified: validationFailureAction=%s → severity=%s (name=%s)", tt.action, c.Severity, c.Name)
						break
					}
				}
			})
		}
	})

	// MatchClauseParsing verifies that ClusterPolicies with match.any
	// clauses specifying resource kinds and namespaces are correctly parsed.
	// The constraint should appear in the scoped namespace's ConstraintReport.
	t.Run("MatchClauseParsing", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		ns1, cleanupNS1 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS1)
		ns2, cleanupNS2 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS2)

		sentinelName := "sentinel-kv-match-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns1, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns1, sentinelName, defaultTimeout)

		policyName := "e2e-kv-match-" + rand.String(5)
		// Use Audit to avoid Enforce blocking workload patches.
		cleanupPolicy := createKyvernoClusterPolicy(
			t, sharedDynamicClient,
			policyName, "Audit",
			[]interface{}{
				kyvernoValidateRule(
					"check-labels",
					kyvernoMatchAnyKindsNamespaces(
						[]string{"Pod", "apps/Deployment"},
						[]string{ns1, ns2},
					),
					"Must have team label",
				),
			},
		)
		t.Cleanup(cleanupPolicy)

		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns1, "e2e-trigger-kv-match")
		t.Cleanup(cleanupTrigger)

		// Verify constraint appears in ns1's workload annotations.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns1, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, policyName)
		})
		require.NotEmpty(t, constraints, "expected Kyverno constraint %q in namespace %s", policyName, ns1)
		t.Logf("Found constraint in scoped namespace %s: name=%s", ns1, policyName)

		// Also verify the ConstraintReport in ns1 includes the constraint.
		waitForReportCondition(t, sharedDynamicClient, ns1, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, policyName) {
					return true
				}
			}
			return false
		})
		t.Logf("ConstraintReport in %s includes Kyverno constraint %s", ns1, policyName)
	})

	// PolicyDeletion verifies that deleting a Kyverno ClusterPolicy
	// removes all its rule-constraints from workload annotations and the ConstraintReport.
	t.Run("PolicyDeletion", func(t *testing.T) {
		t.Parallel()
		requireKyvernoInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-kv-del-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		policyName := "e2e-kv-delete-" + rand.String(5)
		cleanupPolicy := createKyvernoClusterPolicy(
			t, sharedDynamicClient,
			policyName, "Enforce",
			[]interface{}{
				kyvernoValidateRule("check-labels", kyvernoMatchAnyKindsNamespaces([]string{"Pod"}, []string{ns}), "Must have team label"),
			},
		)
		// Keep cleanup in case test fails before manual delete.
		t.Cleanup(cleanupPolicy)

		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-kv-del")
		t.Cleanup(cleanupTrigger)

		// Phase 1: Wait for constraint to appear in workload annotations.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, kyvernoAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, policyName)
		})
		require.NotEmpty(t, constraints, "phase 1: expected constraint %q in annotations before deletion", policyName)
		t.Logf("Phase 1: Constraint appeared in annotations: %s", policyName)

		// Also verify it's in the ConstraintReport.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, policyName) {
					return true
				}
			}
			return false
		})
		t.Log("Phase 1: Constraint appeared in ConstraintReport")

		// Phase 2: Delete the ClusterPolicy.
		err := sharedDynamicClient.Resource(clusterPolicyGVR).Delete(
			context.Background(), policyName, metav1.DeleteOptions{},
		)
		require.NoError(t, err, "failed to delete ClusterPolicy %s", policyName)
		t.Logf("Phase 2: Deleted ClusterPolicy %s", policyName)

		// Phase 3: Verify constraint is removed from workload annotations.
		depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
		waitForCondition(t, kyvernoAnnotationTimeout, defaultPollInterval, func() (bool, error) {
			dep, err := sharedDynamicClient.Resource(depGVR).Namespace(ns).Get(
				context.Background(), sentinelName, metav1.GetOptions{},
			)
			if err != nil {
				return false, err
			}
			annots := dep.GetAnnotations()
			if annots == nil {
				return true, nil // no annotations means no constraints
			}
			raw, ok := annots[annotations.WorkloadConstraints]
			if !ok {
				return true, nil
			}
			// Check if any constraint still references the deleted policy.
			return !strings.Contains(raw, policyName), nil
		})
		t.Log("Phase 3: Constraint removed from workload annotations")

		// Phase 4: Verify constraint is removed from the ConstraintReport.
		waitForReportCondition(t, sharedDynamicClient, ns, reportUpdateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, policyName) {
					return false // still present
				}
			}
			return true // gone
		})
		t.Log("Phase 4: Constraint removed from ConstraintReport")
	})
}
