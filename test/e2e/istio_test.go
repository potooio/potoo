//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the Istio adapter.
// These tests require Istio CRDs to be installed in the cluster
// (via make e2e-setup or make e2e-setup-dd). Tests skip gracefully
// if Istio CRDs are absent. No Istio control plane is required.
package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
)

// Istio GVRs.
var (
	authorizationPolicyGVR = schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "authorizationpolicies",
	}
	peerAuthenticationGVR = schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "peerauthentications",
	}
	sidecarGVR = schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1",
		Resource: "sidecars",
	}
)

const (
	// istioAnnotationTimeout accounts for: CRD rescan (30s) + informer sync +
	// adapter parse + indexer upsert + debounce (30s) + annotator patch.
	// Use 180s to accommodate parallel test contention on single-node clusters.
	istioAnnotationTimeout = 180 * time.Second
)

// requireIstioInstalled skips the test if Istio CRDs are not installed.
func requireIstioInstalled(t *testing.T, dynamicClient dynamic.Interface) {
	t.Helper()
	_, err := dynamicClient.Resource(crdGVR).Get(
		context.Background(), "authorizationpolicies.security.istio.io", metav1.GetOptions{},
	)
	if err != nil {
		t.Skip("Skipping: Istio CRDs not installed (authorizationpolicies.security.istio.io not found)")
	}
}

// createAuthorizationPolicy creates an Istio AuthorizationPolicy in the given namespace.
// Returns a cleanup function.
func createAuthorizationPolicy(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, name, action string,
	selector map[string]interface{},
	rules []interface{},
) func() {
	t.Helper()
	spec := map[string]interface{}{}
	if action != "" {
		spec["action"] = action
	}
	if selector != nil {
		spec["selector"] = map[string]interface{}{
			"matchLabels": selector,
		}
	}
	if rules != nil {
		spec["rules"] = rules
	}

	ap := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1",
			"kind":       "AuthorizationPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
	_, err := dynamicClient.Resource(authorizationPolicyGVR).Namespace(namespace).Create(
		context.Background(), ap, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create AuthorizationPolicy %s/%s", namespace, name)
	t.Logf("Created AuthorizationPolicy: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(authorizationPolicyGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createPeerAuthentication creates an Istio PeerAuthentication in the given namespace.
// Returns a cleanup function.
func createPeerAuthentication(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, name, mtlsMode string,
	selector map[string]interface{},
) func() {
	t.Helper()
	spec := map[string]interface{}{}
	if mtlsMode != "" {
		spec["mtls"] = map[string]interface{}{
			"mode": mtlsMode,
		}
	}
	if selector != nil {
		spec["selector"] = map[string]interface{}{
			"matchLabels": selector,
		}
	}

	pa := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1",
			"kind":       "PeerAuthentication",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
	_, err := dynamicClient.Resource(peerAuthenticationGVR).Namespace(namespace).Create(
		context.Background(), pa, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create PeerAuthentication %s/%s", namespace, name)
	t.Logf("Created PeerAuthentication: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(peerAuthenticationGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createSidecarResource creates an Istio Sidecar in the given namespace.
// Returns a cleanup function.
func createSidecarResource(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, name string,
	workloadLabels map[string]interface{},
	egressHosts []interface{},
) func() {
	t.Helper()
	spec := map[string]interface{}{}
	if workloadLabels != nil {
		spec["workloadSelector"] = map[string]interface{}{
			"labels": workloadLabels,
		}
	}
	if egressHosts != nil {
		spec["egress"] = []interface{}{
			map[string]interface{}{
				"hosts": egressHosts,
			},
		}
	}

	sc := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1",
			"kind":       "Sidecar",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
	_, err := dynamicClient.Resource(sidecarGVR).Namespace(namespace).Create(
		context.Background(), sc, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create Sidecar %s/%s", namespace, name)
	t.Logf("Created Sidecar: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(sidecarGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

func TestIstio(t *testing.T) {
	t.Parallel()
	requireIstioInstalled(t, sharedDynamicClient)

	t.Run("AuthorizationPolicyDiscovery", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("deny-ext-%s", suffix)
		deployName := fmt.Sprintf("istio-ap-%s", suffix)

		// Create a DENY AuthorizationPolicy.
		cleanupAP := createAuthorizationPolicy(t, sharedDynamicClient, ns, policyName, "DENY",
			nil, // No selector — applies to all workloads in namespace
			[]interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"namespaces": []interface{}{"untrusted"},
							},
						},
					},
				},
			},
		)
		defer cleanupAP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace now that both the
		// constraint and the deployment exist.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-istio-ap")
		defer cleanupTrigger()

		// Wait for the constraint to appear in workload annotations.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			istioAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "authorizationpolicies" &&
					c.Name == policyName
			})

		// Verify constraint fields.
		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "AuthorizationPolicy constraint not found in annotations")
		assert.Equal(t, "MeshPolicy", matched.Type)
		assert.Equal(t, "Critical", matched.Severity)
	})

	t.Run("PeerAuthenticationMTLSMode", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("strict-mtls-%s", suffix)
		deployName := fmt.Sprintf("istio-pa-%s", suffix)

		// Create a STRICT PeerAuthentication.
		cleanupPA := createPeerAuthentication(t, sharedDynamicClient, ns, policyName, "STRICT", nil)
		defer cleanupPA()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-istio-pa")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			istioAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "peerauthentications" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "PeerAuthentication constraint not found in annotations")
		assert.Equal(t, "MeshPolicy", matched.Type)
		assert.Equal(t, "Warning", matched.Severity)
	})

	t.Run("SidecarEgressRestriction", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		sidecarName := fmt.Sprintf("restrict-egress-%s", suffix)
		deployName := fmt.Sprintf("istio-sc-%s", suffix)

		// Create a Sidecar with egress restrictions.
		cleanupSC := createSidecarResource(t, sharedDynamicClient, ns, sidecarName,
			nil, // No selector — namespace-wide
			[]interface{}{"./*", "istio-system/*"},
		)
		defer cleanupSC()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-istio-sc")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			istioAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "sidecars" &&
					c.Name == sidecarName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == sidecarName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "Sidecar constraint not found in annotations")
		assert.Equal(t, "MeshPolicy", matched.Type)
		assert.Equal(t, "Info", matched.Severity)
	})

	t.Run("DeletionLifecycle", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("lifecycle-%s", suffix)
		deployName := fmt.Sprintf("istio-del-%s", suffix)

		// Deploy a test workload first.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Create an AuthorizationPolicy.
		cleanupAP := createAuthorizationPolicy(t, sharedDynamicClient, ns, policyName, "DENY",
			nil,
			[]interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"namespaces": []interface{}{"blocked"},
							},
						},
					},
				},
			},
		)

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-istio-del")
		defer cleanupTrigger()

		// Wait for it to appear.
		waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			istioAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "authorizationpolicies" &&
					c.Name == policyName
			})
		t.Log("AuthorizationPolicy constraint appeared in annotations")

		// Delete the policy.
		cleanupAP()
		t.Log("Deleted AuthorizationPolicy, waiting for constraint to disappear...")

		// Wait for the constraint to be removed from annotations.
		waitForNoConstraintMatch(t, sharedDynamicClient, ns, deployName,
			istioAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "authorizationpolicies" &&
					c.Name == policyName
			})
		t.Log("AuthorizationPolicy constraint removed from annotations")
	})

	t.Run("ConstraintReport", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("report-%s", suffix)
		deployName := fmt.Sprintf("istio-rpt-%s", suffix)

		// Create workload and AuthorizationPolicy.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		cleanupAP := createAuthorizationPolicy(t, sharedDynamicClient, ns, policyName, "ALLOW",
			nil,
			[]interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"principals": []interface{}{"cluster.local/ns/default/sa/app"},
							},
						},
					},
				},
			},
		)
		defer cleanupAP()

		// Verify constraint appears in the ConstraintReport.
		constraintReportGVR := schema.GroupVersionResource{
			Group:    "potoo.io",
			Version:  "v1alpha1",
			Resource: "constraintreports",
		}
		waitForCondition(t, istioAnnotationTimeout, defaultPollInterval, func() (bool, error) {
			report, err := sharedDynamicClient.Resource(constraintReportGVR).Namespace(ns).Get(
				context.Background(), "constraints", metav1.GetOptions{},
			)
			if err != nil {
				return false, nil
			}
			mr, ok, _ := unstructured.NestedMap(report.Object, "status", "machineReadable")
			if !ok || mr == nil {
				return false, nil
			}
			constraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
			if !ok {
				return false, nil
			}
			for _, raw := range constraints {
				entry, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				if entry["name"] == policyName {
					t.Logf("Found constraint %s in ConstraintReport", policyName)
					return true, nil
				}
			}
			return false, nil
		})
	})
}
