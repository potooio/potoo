//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the Gatekeeper adapter.
// These tests require Gatekeeper to be installed in the cluster
// (via make e2e-setup or make e2e-setup-dd). Tests skip gracefully
// if Gatekeeper CRDs are absent.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"

	"github.com/potooio/potoo/internal/annotations"
)

// Gatekeeper GVRs.
var (
	constraintTemplateGVR = schema.GroupVersionResource{
		Group:    "templates.gatekeeper.sh",
		Version:  "v1",
		Resource: "constrainttemplates",
	}

	crdGVR = schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}
)

const (
	// gatekeeperCRDEstablishTimeout is the time to wait for a Gatekeeper-generated CRD
	// to become established after creating a ConstraintTemplate.
	gatekeeperCRDEstablishTimeout = 60 * time.Second

	// gatekeeperAnnotationTimeout accounts for: CRD rescan (30s) + informer sync +
	// adapter parse + indexer upsert + debounce (30s) + annotator patch.
	// Use 180s to accommodate parallel test contention on single-node clusters.
	gatekeeperAnnotationTimeout = 180 * time.Second
)

// requireGatekeeperInstalled skips the test if Gatekeeper CRDs are not installed.
func requireGatekeeperInstalled(t *testing.T, dynamicClient dynamic.Interface) {
	t.Helper()
	_, err := dynamicClient.Resource(crdGVR).Get(
		context.Background(), "constrainttemplates.templates.gatekeeper.sh", metav1.GetOptions{},
	)
	if err != nil {
		t.Skip("Skipping: Gatekeeper CRDs not installed (constrainttemplates.templates.gatekeeper.sh not found)")
	}
}

// createK8sRequiredLabelsTemplate creates the K8sRequiredLabels ConstraintTemplate
// and waits for the generated CRD to become established. Returns a cleanup function.
func createK8sRequiredLabelsTemplate(t *testing.T, dynamicClient dynamic.Interface) func() {
	t.Helper()

	template := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "templates.gatekeeper.sh/v1",
			"kind":       "ConstraintTemplate",
			"metadata": map[string]interface{}{
				"name": "k8srequiredlabels",
			},
			"spec": map[string]interface{}{
				"crd": map[string]interface{}{
					"spec": map[string]interface{}{
						"names": map[string]interface{}{
							"kind": "K8sRequiredLabels",
						},
						"validation": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"labels": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"key": map[string]interface{}{
													"type": "string",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				"targets": []interface{}{
					map[string]interface{}{
						"target": "admission.k8s.gatekeeper.sh",
						"rego": `package k8srequiredlabels
violation[{"msg": msg}] {
  provided := {label | input.review.object.metadata.labels[label]}
  required := {label | label := input.parameters.labels[_].key}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("Missing required labels: %v", [missing])
}`,
					},
				},
			},
		},
	}

	// Use create-or-reuse semantics. If the template exists from a previous
	// test run, reuse it rather than deleting/recreating, which causes CRD
	// churn and leaves the controller's dynamic informers in a stale state.
	_, err := dynamicClient.Resource(constraintTemplateGVR).Create(
		context.Background(), template, metav1.CreateOptions{},
	)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err, "failed to create K8sRequiredLabels template")
	}
	if apierrors.IsAlreadyExists(err) {
		t.Log("K8sRequiredLabels template already exists, reusing")
	}

	// Wait for the generated CRD to become established.
	generatedCRD := "k8srequiredlabels.constraints.gatekeeper.sh"
	waitForCRDEstablished(t, dynamicClient, generatedCRD)

	// Return no-op cleanup. ConstraintTemplates are intentionally left in
	// the cluster to keep the controller's dynamic informers healthy.
	// Full cleanup is handled by make e2e-teardown.
	return func() {}
}

// createK8sAllowedReposTemplate creates the K8sAllowedRepos ConstraintTemplate
// and waits for the generated CRD to become established. Returns a cleanup function.
func createK8sAllowedReposTemplate(t *testing.T, dynamicClient dynamic.Interface) func() {
	t.Helper()

	template := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "templates.gatekeeper.sh/v1",
			"kind":       "ConstraintTemplate",
			"metadata": map[string]interface{}{
				"name": "k8sallowedrepos",
			},
			"spec": map[string]interface{}{
				"crd": map[string]interface{}{
					"spec": map[string]interface{}{
						"names": map[string]interface{}{
							"kind": "K8sAllowedRepos",
						},
						"validation": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"repos": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"type": "string",
										},
									},
								},
							},
						},
					},
				},
				"targets": []interface{}{
					map[string]interface{}{
						"target": "admission.k8s.gatekeeper.sh",
						"rego": `package k8sallowedrepos
violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  satisfied := [good | repo = input.parameters.repos[_]; good = startswith(container.image, repo)]
  not any(satisfied)
  msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}`,
					},
				},
			},
		},
	}

	_, err := dynamicClient.Resource(constraintTemplateGVR).Create(
		context.Background(), template, metav1.CreateOptions{},
	)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err, "failed to create K8sAllowedRepos template")
	}
	if apierrors.IsAlreadyExists(err) {
		t.Log("K8sAllowedRepos template already exists, reusing")
	}

	generatedCRD := "k8sallowedrepos.constraints.gatekeeper.sh"
	waitForCRDEstablished(t, dynamicClient, generatedCRD)

	return func() {}
}

// waitForCRDEstablished polls a CRD until its status conditions include Established=True.
func waitForCRDEstablished(t *testing.T, dynamicClient dynamic.Interface, crdName string) {
	t.Helper()
	t.Logf("Waiting for CRD %s to become established...", crdName)

	waitForCondition(t, gatekeeperCRDEstablishTimeout, defaultPollInterval, func() (bool, error) {
		obj, err := dynamicClient.Resource(crdGVR).Get(
			context.Background(), crdName, metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		conditions, ok, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
		if !ok || conditions == nil {
			return false, nil
		}
		for _, condRaw := range conditions {
			cond, ok := condRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if cond["type"] == "Established" && cond["status"] == "True" {
				t.Logf("CRD %s is established", crdName)
				return true, nil
			}
		}
		return false, nil
	})
}

// createGatekeeperConstraint creates a Gatekeeper constraint instance.
// kind is the ConstraintTemplate kind (e.g., "K8sRequiredLabels").
// The constraint is cluster-scoped; matchNamespaces scopes which namespaces are affected.
func createGatekeeperConstraint(
	t *testing.T,
	dynamicClient dynamic.Interface,
	kind, name, enforcementAction string,
	matchNamespaces []string,
	matchKinds []interface{},
	parameters map[string]interface{},
) func() {
	t.Helper()

	// Gatekeeper generates CRDs with plural = lowercased Kind (no extra "s").
	resource := strings.ToLower(kind)
	gvr := schema.GroupVersionResource{
		Group:    "constraints.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: resource,
	}

	spec := map[string]interface{}{
		"enforcementAction": enforcementAction,
	}

	match := map[string]interface{}{}
	if len(matchNamespaces) > 0 {
		nsSlice := make([]interface{}, len(matchNamespaces))
		for i, ns := range matchNamespaces {
			nsSlice[i] = ns
		}
		match["namespaces"] = nsSlice
	}
	if len(matchKinds) > 0 {
		match["kinds"] = matchKinds
	}
	if len(match) > 0 {
		spec["match"] = match
	}

	if parameters != nil {
		spec["parameters"] = parameters
	}

	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": spec,
		},
	}

	// Retry creation: the CRD API endpoint may take a moment to become served
	// after the CRD reaches Established status.
	var createErr error
	waitForCondition(t, 15*time.Second, defaultPollInterval, func() (bool, error) {
		_, createErr = dynamicClient.Resource(gvr).Create(
			context.Background(), constraint, metav1.CreateOptions{},
		)
		return createErr == nil, nil
	})
	require.NoError(t, createErr, "failed to create %s %s", kind, name)
	t.Logf("Created Gatekeeper constraint: %s/%s (enforcementAction=%s)", kind, name, enforcementAction)

	return func() {
		deleteUnstructured(t, dynamicClient, gvr, "", name)
	}
}

// TestGatekeeper is the top-level test that contains all Gatekeeper E2E subtests.
func TestGatekeeper(t *testing.T) {
	t.Parallel()

	// ConstraintDiscovery verifies that creating a ConstraintTemplate
	// and constraint instance causes the constraint to be auto-discovered, indexed,
	// and annotated on workloads.
	t.Run("ConstraintDiscovery", func(t *testing.T) {
		t.Parallel()
		requireGatekeeperInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-gk-disc-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		// Create the ConstraintTemplate (generates the K8sRequiredLabels CRD).
		cleanupTemplate := createK8sRequiredLabelsTemplate(t, sharedDynamicClient)

		// Create a constraint scoped to the test namespace.
		constraintName := "e2e-require-labels-" + rand.String(5)
		cleanupConstraint := createGatekeeperConstraint(
			t, sharedDynamicClient,
			"K8sRequiredLabels", constraintName, "deny",
			[]string{ns},
			[]interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"kinds":     []interface{}{"Pod"},
				},
			},
			map[string]interface{}{
				"labels": []interface{}{
					map[string]interface{}{"key": "team"},
				},
			},
		)
		// LIFO: constraint deletes first, then template (avoids GVR disappearing).
		t.Cleanup(cleanupTemplate)
		t.Cleanup(cleanupConstraint)

		// Gatekeeper constraints are cluster-scoped. Create a namespace-scoped
		// trigger to force the workload annotator to process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-gk-disc")
		t.Cleanup(cleanupTrigger)

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, constraintName)
		})
		require.NotEmpty(t, constraints, "expected Admission constraint containing %q", constraintName)

		for _, c := range constraints {
			if c.Type == "Admission" && strings.Contains(c.Name, constraintName) {
				assert.Equal(t, "Critical", c.Severity, "deny enforcement should map to Critical severity")
				t.Logf("Found Gatekeeper constraint: type=%s name=%s source=%s severity=%s", c.Type, c.Name, c.Source, c.Severity)
				break
			}
		}
	})

	// EnforcementMapping verifies that Gatekeeper enforcement actions
	// map to the correct Potoo severity levels:
	//
	//	deny   -> Critical
	//	warn   -> Warning
	//	dryrun -> Info
	t.Run("EnforcementMapping", func(t *testing.T) {
		t.Parallel()
		requireGatekeeperInstalled(t, sharedDynamicClient)

		// Create the shared ConstraintTemplate.
		cleanupTemplate := createK8sRequiredLabelsTemplate(t, sharedDynamicClient)
		t.Cleanup(cleanupTemplate)

		tests := []struct {
			action   string
			severity string
		}{
			{"deny", "Critical"},
			{"warn", "Warning"},
			{"dryrun", "Info"},
		}

		for _, tt := range tests {
			t.Run(tt.action, func(t *testing.T) {
				ns, cleanupNS := createTestNamespace(t, sharedClientset)
				t.Cleanup(cleanupNS)

				sentinelName := "sentinel-gk-" + tt.action + "-" + rand.String(5)
				cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
				t.Cleanup(cleanup)
				waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

				constraintName := fmt.Sprintf("e2e-enforce-%s-%s", tt.action, rand.String(5))
				cleanupConstraint := createGatekeeperConstraint(
					t, sharedDynamicClient,
					"K8sRequiredLabels", constraintName, tt.action,
					[]string{ns},
					[]interface{}{
						map[string]interface{}{
							"apiGroups": []interface{}{""},
							"kinds":     []interface{}{"Pod"},
						},
					},
					map[string]interface{}{
						"labels": []interface{}{
							map[string]interface{}{"key": "team"},
						},
					},
				)
				t.Cleanup(cleanupConstraint)

				// Trigger annotator for this namespace.
				cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-gk-"+tt.action)
				t.Cleanup(cleanupTrigger)

				constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
					return c.Type == "Admission" && strings.Contains(c.Name, constraintName)
				})
				require.NotEmpty(t, constraints, "expected Admission constraint %q for enforcementAction=%s", constraintName, tt.action)

				for _, c := range constraints {
					if c.Type == "Admission" && strings.Contains(c.Name, constraintName) {
						assert.Equal(t, tt.severity, c.Severity,
							"enforcementAction=%s should map to severity=%s", tt.action, tt.severity)
						t.Logf("Verified: enforcementAction=%s -> severity=%s (name=%s)", tt.action, c.Severity, c.Name)
						break
					}
				}
			})
		}
	})

	// MatchBlockParsing verifies that constraints scoped to specific
	// namespaces and resource kinds are correctly parsed by the adapter. The constraint
	// is created with explicit match.namespaces and match.kinds, and we verify the
	// ConstraintReport includes the constraint in the scoped namespace.
	t.Run("MatchBlockParsing", func(t *testing.T) {
		t.Parallel()
		requireGatekeeperInstalled(t, sharedDynamicClient)

		// Create two test namespaces that the constraint will scope to.
		ns1, cleanupNS1 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS1)
		ns2, cleanupNS2 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS2)

		// Create sentinel BEFORE the constraint so Gatekeeper's deny action
		// doesn't block Pod creation.
		sentinelName := "sentinel-gk-match-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns1, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns1, sentinelName, defaultTimeout)

		cleanupTemplate := createK8sRequiredLabelsTemplate(t, sharedDynamicClient)
		t.Cleanup(cleanupTemplate)

		// Use "warn" enforcement: this test validates match block parsing, not
		// enforcement. "deny" would block the annotator's Deployment patch
		// (matchKinds includes Deployment) creating a catch-22.
		constraintName := "e2e-match-block-" + rand.String(5)
		cleanupConstraint := createGatekeeperConstraint(
			t, sharedDynamicClient,
			"K8sRequiredLabels", constraintName, "warn",
			[]string{ns1, ns2},
			[]interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"kinds":     []interface{}{"Pod"},
				},
				map[string]interface{}{
					"apiGroups": []interface{}{"apps"},
					"kinds":     []interface{}{"Deployment"},
				},
			},
			map[string]interface{}{
				"labels": []interface{}{
					map[string]interface{}{"key": "env"},
				},
			},
		)
		t.Cleanup(cleanupConstraint)

		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns1, "e2e-trigger-gk-match")
		t.Cleanup(cleanupTrigger)

		// Verify constraint appears in ns1's workload annotations.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns1, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, constraintName)
		})
		require.NotEmpty(t, constraints, "expected Gatekeeper constraint %q in namespace %s", constraintName, ns1)
		t.Logf("Found constraint in scoped namespace %s: name=%s", ns1, constraintName)

		// Also verify the ConstraintReport in ns1 includes the constraint.
		waitForReportCondition(t, sharedDynamicClient, ns1, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, constraintName) {
					return true
				}
			}
			return false
		})
		t.Logf("ConstraintReport in %s includes Gatekeeper constraint %s", ns1, constraintName)
	})

	// MultipleConstraintTypes verifies that constraints from different
	// ConstraintTemplates are all discovered dynamically — proving the adapter is not
	// hardcoded to specific constraint kinds.
	t.Run("MultipleConstraintTypes", func(t *testing.T) {
		t.Parallel()
		requireGatekeeperInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-gk-multi-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		// Create both ConstraintTemplates.
		cleanupLabelsTemplate := createK8sRequiredLabelsTemplate(t, sharedDynamicClient)
		cleanupReposTemplate := createK8sAllowedReposTemplate(t, sharedDynamicClient)
		// Templates cleaned up last (after constraints).
		t.Cleanup(cleanupLabelsTemplate)
		t.Cleanup(cleanupReposTemplate)

		// Create a K8sRequiredLabels constraint.
		labelsConstraintName := "e2e-multi-labels-" + rand.String(5)
		cleanupLabels := createGatekeeperConstraint(
			t, sharedDynamicClient,
			"K8sRequiredLabels", labelsConstraintName, "deny",
			[]string{ns},
			[]interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"kinds":     []interface{}{"Pod"},
				},
			},
			map[string]interface{}{
				"labels": []interface{}{
					map[string]interface{}{"key": "team"},
				},
			},
		)
		t.Cleanup(cleanupLabels)

		// Create a K8sAllowedRepos constraint.
		reposConstraintName := "e2e-multi-repos-" + rand.String(5)
		cleanupRepos := createGatekeeperConstraint(
			t, sharedDynamicClient,
			"K8sAllowedRepos", reposConstraintName, "warn",
			[]string{ns},
			[]interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"kinds":     []interface{}{"Pod"},
				},
			},
			map[string]interface{}{
				"repos": []interface{}{"gcr.io/", "docker.io/"},
			},
		)
		t.Cleanup(cleanupRepos)

		// Trigger annotator.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-gk-multi")
		t.Cleanup(cleanupTrigger)

		// Wait for BOTH constraint types to appear in workload annotations.
		// We poll until we find both, since the discovery engine may need separate
		// rescan cycles to discover each CRD.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, labelsConstraintName)
		})
		require.NotEmpty(t, summaries, "expected K8sRequiredLabels constraint %q in annotations", labelsConstraintName)

		// Labels constraint found; now wait for repos constraint too.
		summaries = waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, reposConstraintName)
		})
		require.NotEmpty(t, summaries, "expected K8sAllowedRepos constraint %q in annotations", reposConstraintName)

		// Verify severity mapping for both constraints.
		for _, c := range summaries {
			if c.Type == "Admission" && strings.Contains(c.Name, labelsConstraintName) {
				assert.Equal(t, "Critical", c.Severity, "K8sRequiredLabels (deny) should be Critical")
				t.Logf("Found K8sRequiredLabels constraint: name=%s source=%s severity=%s", c.Name, c.Source, c.Severity)
			}
			if c.Type == "Admission" && strings.Contains(c.Name, reposConstraintName) {
				assert.Equal(t, "Warning", c.Severity, "K8sAllowedRepos (warn) should be Warning")
				t.Logf("Found K8sAllowedRepos constraint: name=%s source=%s severity=%s", c.Name, c.Source, c.Severity)
			}
		}
	})

	// ConstraintDeletion verifies that deleting a Gatekeeper constraint
	// removes it from the workload annotations and the ConstraintReport.
	t.Run("ConstraintDeletion", func(t *testing.T) {
		t.Parallel()
		requireGatekeeperInstalled(t, sharedDynamicClient)

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-gk-del-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, defaultTimeout)

		cleanupTemplate := createK8sRequiredLabelsTemplate(t, sharedDynamicClient)
		t.Cleanup(cleanupTemplate)

		constraintName := "e2e-delete-test-" + rand.String(5)
		constraintGVR := schema.GroupVersionResource{
			Group:    "constraints.gatekeeper.sh",
			Version:  "v1beta1",
			Resource: "k8srequiredlabels",
		}

		cleanupConstraint := createGatekeeperConstraint(
			t, sharedDynamicClient,
			"K8sRequiredLabels", constraintName, "deny",
			[]string{ns},
			[]interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"kinds":     []interface{}{"Pod"},
				},
			},
			map[string]interface{}{
				"labels": []interface{}{
					map[string]interface{}{"key": "team"},
				},
			},
		)
		// Keep cleanup in case test fails before manual delete.
		t.Cleanup(cleanupConstraint)

		// Trigger annotator.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-gk-del")
		t.Cleanup(cleanupTrigger)

		// Phase 1: Wait for constraint to appear in workload annotations.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, gatekeeperAnnotationTimeout, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, constraintName)
		})
		require.NotEmpty(t, constraints, "phase 1: expected constraint %q in annotations before deletion", constraintName)
		t.Logf("Phase 1: Constraint appeared in annotations: %s", constraintName)

		// Also verify it's in the ConstraintReport.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, constraintName) {
					return true
				}
			}
			return false
		})
		t.Log("Phase 1: Constraint appeared in ConstraintReport")

		// Phase 2: Delete the constraint.
		err := sharedDynamicClient.Resource(constraintGVR).Delete(
			context.Background(), constraintName, metav1.DeleteOptions{},
		)
		require.NoError(t, err, "failed to delete constraint %s", constraintName)
		t.Logf("Phase 2: Deleted constraint %s", constraintName)

		// Phase 3: Wait for constraint to be removed from ConstraintReport.
		waitForReportCondition(t, sharedDynamicClient, ns, reportUpdateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if strings.Contains(n, constraintName) {
					return false // still present
				}
			}
			return true // gone
		})
		t.Log("Phase 3: Constraint removed from ConstraintReport")

		// Phase 4: Verify constraint is removed from workload annotations.
		// The annotator debounces updates, so wait for the annotation to be refreshed.
		depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
		waitForCondition(t, workloadAnnotationTimeout, defaultPollInterval, func() (bool, error) {
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
			var current []constraintSummary
			if err := json.Unmarshal([]byte(raw), &current); err != nil {
				return false, err
			}
			for _, c := range current {
				if strings.Contains(c.Name, constraintName) {
					return false, nil // still present
				}
			}
			return true, nil
		})
		t.Log("Phase 4: Constraint removed from workload annotations")
	})
}
