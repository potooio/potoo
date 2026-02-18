//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for Potoo's core discovery engine
// and native Kubernetes adapters. These tests require a running cluster with the
// controller deployed (via make e2e-setup or make e2e-setup-dd).
//
// The rescan interval should be set to 15s in the E2E deployment for the
// periodic rescan test to complete in a reasonable time.
//
// Each discovery test creates its own namespace to avoid interference from the
// workload annotator's configurable namespace workload cache. When tests share a
// namespace, cleanup-triggered cache refreshes can cause subsequent tests'
// sentinels to be invisible to the annotator.
package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
)

func TestDiscovery(t *testing.T) {
	t.Parallel()

	// TestNetworkPolicyDiscovery verifies that deploying a NetworkPolicy causes
	// it to appear in the constraint index and annotate workloads within 30s.
	t.Run("NetworkPolicy", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-netpol-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// Create a deny-all egress NetworkPolicy.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-deny-egress",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, np)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "e2e-deny-egress")
		})

		// Wait for the specific NetworkEgress constraint to appear in annotations.
		// Using waitForConstraintMatch instead of getWorkloadConstraints to avoid
		// returning stale data when cluster-scoped constraints already populate
		// the annotation before this test's NetworkPolicy is indexed.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "NetworkEgress"
		})
		require.NotEmpty(t, constraints, "expected NetworkEgress constraint in workload annotations")
		for _, c := range constraints {
			if c.Type == "NetworkEgress" {
				t.Logf("Found NetworkEgress constraint: name=%s source=%s", c.Name, c.Source)
				break
			}
		}
	})

	// TestResourceQuotaDiscovery verifies that deploying a ResourceQuota causes a
	// ResourceLimit constraint to appear in workload annotations.
	t.Run("ResourceQuota", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-quota-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		rq := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ResourceQuota",
				"metadata": map[string]interface{}{
					"name":      "e2e-resource-quota",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"hard": map[string]interface{}{
						"cpu":    "10",
						"memory": "10Gi",
						"pods":   "20",
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, rq)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "", Version: "v1", Resource: "resourcequotas",
			}, ns, "e2e-resource-quota")
		})

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "ResourceLimit" && c.Source == "resourcequotas"
		})
		require.NotEmpty(t, constraints, "expected ResourceLimit constraint from resourcequotas")
		for _, c := range constraints {
			if c.Type == "ResourceLimit" && c.Source == "resourcequotas" {
				t.Logf("Found ResourceLimit constraint from ResourceQuota: name=%s severity=%s", c.Name, c.Severity)
				break
			}
		}
	})

	// TestLimitRangeDiscovery verifies that deploying a LimitRange causes a
	// ResourceLimit constraint with default/min/max values to be indexed.
	t.Run("LimitRange", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-lr-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		lr := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "LimitRange",
				"metadata": map[string]interface{}{
					"name":      "e2e-limit-range",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"limits": []interface{}{
						map[string]interface{}{
							"type": "Container",
							"default": map[string]interface{}{
								"cpu":    "500m",
								"memory": "256Mi",
							},
							"defaultRequest": map[string]interface{}{
								"cpu":    "100m",
								"memory": "128Mi",
							},
							"min": map[string]interface{}{
								"cpu":    "50m",
								"memory": "64Mi",
							},
							"max": map[string]interface{}{
								"cpu":    "2",
								"memory": "1Gi",
							},
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, lr)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "", Version: "v1", Resource: "limitranges",
			}, ns, "e2e-limit-range")
		})

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "ResourceLimit" && c.Source == "limitranges"
		})
		require.NotEmpty(t, constraints, "expected ResourceLimit constraint from limitranges")
		for _, c := range constraints {
			if c.Type == "ResourceLimit" && c.Source == "limitranges" {
				t.Logf("Found ResourceLimit constraint from LimitRange: name=%s severity=%s", c.Name, c.Severity)
				break
			}
		}
	})

	// TestValidatingWebhookDiscovery verifies that creating a ValidatingWebhookConfiguration
	// causes an Admission constraint to be discovered and indexed.
	t.Run("ValidatingWebhook", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-vwh-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		webhookName := "e2e-validating-webhook-" + rand.String(5)
		vwh := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "admissionregistration.k8s.io/v1",
				"kind":       "ValidatingWebhookConfiguration",
				"metadata": map[string]interface{}{
					"name": webhookName,
				},
				"webhooks": []interface{}{
					map[string]interface{}{
						"name":                    "test-validating.e2e.example.com",
						"admissionReviewVersions": []interface{}{"v1"},
						"sideEffects":             "None",
						"failurePolicy":           "Ignore",
						"clientConfig": map[string]interface{}{
							"url": "https://localhost:9443/validate",
						},
						"rules": []interface{}{
							map[string]interface{}{
								"apiGroups":   []interface{}{""},
								"apiVersions": []interface{}{"v1"},
								"operations":  []interface{}{"CREATE", "UPDATE"},
								"resources":   []interface{}{"pods"},
							},
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, vwh)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations",
			}, "", webhookName)
		})

		// Cluster-scoped constraints have Namespace="" so OnIndexChange doesn't
		// queue a namespace update for them. Create a namespace-scoped trigger
		// (NetworkPolicy) so the annotator refreshes this namespace; ByNamespace
		// will then include cluster-scoped webhook constraints too.
		triggerNP := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-trigger-vwh",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, triggerNP)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "e2e-trigger-vwh")
		})

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "Admission" && c.Source == "validatingwebhookconfigurations" && strings.Contains(c.Name, webhookName)
		})
		require.NotEmpty(t, constraints, "expected Admission constraint from validatingwebhookconfigurations containing %q", webhookName)
		for _, c := range constraints {
			if c.Type == "Admission" && c.Source == "validatingwebhookconfigurations" && strings.Contains(c.Name, webhookName) {
				t.Logf("Found Admission constraint from ValidatingWebhookConfiguration: name=%s", c.Name)
				break
			}
		}
	})

	// TestMutatingWebhookDiscovery verifies that creating a MutatingWebhookConfiguration
	// causes an Admission constraint to be discovered and indexed.
	t.Run("MutatingWebhook", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-mwh-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		webhookName := "e2e-mutating-webhook-" + rand.String(5)
		mwh := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "admissionregistration.k8s.io/v1",
				"kind":       "MutatingWebhookConfiguration",
				"metadata": map[string]interface{}{
					"name": webhookName,
				},
				"webhooks": []interface{}{
					map[string]interface{}{
						"name":                    "test-mutating.e2e.example.com",
						"admissionReviewVersions": []interface{}{"v1"},
						"sideEffects":             "None",
						"failurePolicy":           "Ignore",
						"clientConfig": map[string]interface{}{
							"url": "https://localhost:9443/mutate",
						},
						"rules": []interface{}{
							map[string]interface{}{
								"apiGroups":   []interface{}{""},
								"apiVersions": []interface{}{"v1"},
								"operations":  []interface{}{"CREATE"},
								"resources":   []interface{}{"pods"},
							},
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, mwh)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations",
			}, "", webhookName)
		})

		// Cluster-scoped constraints need a namespace-scoped trigger to force the
		// workload annotator to process this namespace (see TestValidatingWebhookDiscovery).
		triggerNP := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-trigger-mwh",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, triggerNP)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "e2e-trigger-mwh")
		})

		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "Admission" && c.Source == "mutatingwebhookconfigurations" && strings.Contains(c.Name, webhookName)
		})
		require.NotEmpty(t, constraints, "expected Admission constraint from mutatingwebhookconfigurations containing %q", webhookName)
		for _, c := range constraints {
			if c.Type == "Admission" && c.Source == "mutatingwebhookconfigurations" && strings.Contains(c.Name, webhookName) {
				t.Logf("Found Admission constraint from MutatingWebhookConfiguration: name=%s", c.Name)
				break
			}
		}
	})

	// TestPotooWebhookFiltered verifies that a ValidatingWebhookConfiguration
	// with individual webhook entry names containing "potoo" is filtered out
	// and does NOT produce a constraint.
	//
	// To avoid a vacuously passing test (where the annotator simply hasn't run yet),
	// this test creates both a non-potoo webhook (baseline) and a potoo-owned
	// webhook. It waits for the baseline to appear in constraints, then verifies the
	// potoo-owned webhook was excluded.
	t.Run("PotooWebhookFiltered", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-njwh-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// Create a baseline (non-potoo) webhook so we can confirm the annotator ran.
		baselineName := "e2e-baseline-webhook-" + rand.String(5)
		baselineVwh := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "admissionregistration.k8s.io/v1",
				"kind":       "ValidatingWebhookConfiguration",
				"metadata": map[string]interface{}{
					"name": baselineName,
				},
				"webhooks": []interface{}{
					map[string]interface{}{
						"name":                    "baseline.e2e.example.com",
						"admissionReviewVersions": []interface{}{"v1"},
						"sideEffects":             "None",
						"failurePolicy":           "Ignore",
						"clientConfig": map[string]interface{}{
							"url": "https://localhost:9443/baseline",
						},
						"rules": []interface{}{
							map[string]interface{}{
								"apiGroups":   []interface{}{""},
								"apiVersions": []interface{}{"v1"},
								"operations":  []interface{}{"CREATE"},
								"resources":   []interface{}{"pods"},
							},
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, baselineVwh)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations",
			}, "", baselineName)
		})

		// Create the potoo-owned webhook that should be filtered.
		potooWHName := "e2e-potoo-webhook-" + rand.String(5)
		potooVwh := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "admissionregistration.k8s.io/v1",
				"kind":       "ValidatingWebhookConfiguration",
				"metadata": map[string]interface{}{
					"name": potooWHName,
				},
				"webhooks": []interface{}{
					map[string]interface{}{
						// Individual webhook entry name contains "potoo" — should be filtered.
						"name":                    "potoo-admission.potoo.io",
						"admissionReviewVersions": []interface{}{"v1"},
						"sideEffects":             "None",
						"failurePolicy":           "Ignore",
						"clientConfig": map[string]interface{}{
							"url": "https://localhost:9443/validate",
						},
						"rules": []interface{}{
							map[string]interface{}{
								"apiGroups":   []interface{}{""},
								"apiVersions": []interface{}{"v1"},
								"operations":  []interface{}{"CREATE"},
								"resources":   []interface{}{"pods"},
							},
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, potooVwh)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations",
			}, "", potooWHName)
		})

		// Cluster-scoped constraints need a namespace-scoped trigger to force the
		// workload annotator to process this namespace.
		triggerNP := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-trigger-njwh",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, triggerNP)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "e2e-trigger-njwh")
		})

		// Wait for the baseline constraint to appear — proves the annotator has run.
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Type == "Admission" && strings.Contains(c.Name, baselineName)
		})
		require.NotEmpty(t, constraints, "baseline webhook constraint not found; annotator may not have processed it yet")

		// Now verify no constraint from the potoo-owned webhook exists.
		for _, c := range constraints {
			require.False(t, strings.Contains(c.Name, potooWHName),
				"potoo-owned webhook should have been filtered, but found constraint: %+v", c)
		}
		t.Log("Confirmed: potoo-owned webhook was correctly filtered")
	})

	// TestPeriodicRescanDiscovery verifies that when a new CRD with a policy-like
	// name is installed after the controller is running, the periodic rescan picks
	// it up and the generic adapter parses instances of it.
	t.Run("PeriodicRescan", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		sentinelName := "sentinel-rescan-" + rand.String(5)
		cleanup := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// Create a CRD with a policy-like name so the discovery engine picks it up
		// via the "policy" name hint.
		crdName := "securitypolicies.e2e.potoo.io"
		crd := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "apiextensions.k8s.io/v1",
				"kind":       "CustomResourceDefinition",
				"metadata": map[string]interface{}{
					"name": crdName,
				},
				"spec": map[string]interface{}{
					"group": "e2e.potoo.io",
					"names": map[string]interface{}{
						"plural":   "securitypolicies",
						"singular": "securitypolicy",
						"kind":     "SecurityPolicy",
					},
					"scope": "Namespaced",
					"versions": []interface{}{
						map[string]interface{}{
							"name":    "v1",
							"served":  true,
							"storage": true,
							"schema": map[string]interface{}{
								"openAPIV3Schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"spec": map[string]interface{}{
											"type":                                 "object",
											"x-kubernetes-preserve-unknown-fields": true,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		// Delete any leftover CRD from a previous run before creating.
		_ = sharedDynamicClient.Resource(crdGVR).Delete(context.Background(), crdName, metav1.DeleteOptions{})
		waitForCondition(t, 30*time.Second, defaultPollInterval, func() (bool, error) {
			_, err := sharedDynamicClient.Resource(crdGVR).Get(context.Background(), crdName, metav1.GetOptions{})
			if err != nil {
				return true, nil // CRD is gone
			}
			return false, nil
		})
		applyUnstructured(t, sharedDynamicClient, crd)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, crdGVR, "", crdName)
		})

		// Wait for the CRD to be established.
		waitForCondition(t, 30*time.Second, defaultPollInterval, func() (bool, error) {
			obj, err := sharedDynamicClient.Resource(crdGVR).Get(
				context.Background(), crdName, metav1.GetOptions{},
			)
			if err != nil {
				return false, err
			}
			conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
			for _, condRaw := range conditions {
				cond, ok := condRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if cond["type"] == "Established" && cond["status"] == "True" {
					return true, nil
				}
			}
			return false, nil
		})

		// Create an instance of the custom CRD. The discovery engine's periodic
		// rescan (15s interval in E2E) will pick up the new CRD and start an
		// informer. The CR creation may happen before the informer is watching,
		// but the informer's initial list will catch it.
		crGVR := schema.GroupVersionResource{
			Group: "e2e.potoo.io", Version: "v1", Resource: "securitypolicies",
		}
		cr := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "e2e.potoo.io/v1",
				"kind":       "SecurityPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-security-policy",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": sentinelName,
						},
					},
					"rules": []interface{}{
						map[string]interface{}{
							"action": "deny",
							"from":   "external",
						},
					},
				},
			},
		}

		// The CRD may take a moment to become fully served after "Established".
		// Retry creation briefly to handle the API registration delay.
		var createErr error
		waitForCondition(t, 15*time.Second, defaultPollInterval, func() (bool, error) {
			_, createErr = sharedDynamicClient.Resource(crGVR).Namespace(ns).Create(
				context.Background(), cr, metav1.CreateOptions{},
			)
			return createErr == nil, nil
		})
		require.NoError(t, createErr, "failed to create SecurityPolicy CR")
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, crGVR, ns, "e2e-security-policy")
		})

		// Wait for the generic adapter to pick it up and annotate the workload.
		// Use a longer timeout (120s) to cover up to two rescan cycles plus
		// informer sync and annotation processing time.
		// Using waitForConstraintMatch to poll until the specific constraint
		// appears, avoiding stale reads when cluster-scoped constraints already
		// populate the annotation.
		t.Log("Waiting for periodic rescan to discover the new CRD and index the CR...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, 180*time.Second, func(c constraintSummary) bool {
			return c.Source == "securitypolicies"
		})
		require.NotEmpty(t, constraints, "no securitypolicies constraint found on sentinel deployment after rescan")
		for _, c := range constraints {
			if c.Source == "securitypolicies" {
				t.Logf("Found constraint from generic adapter: type=%s name=%s source=%s", c.Type, c.Name, c.Source)
				break
			}
		}
	})
}
