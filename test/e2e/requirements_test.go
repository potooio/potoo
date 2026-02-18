//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for Potoo's missing resource detection
// (requirements evaluator). These tests verify that the requirement rules detect
// absent companion resources, emit alerts after the debounce window, resolve alerts
// when resources appear, and properly debounce delete-recreate cycles.
//
// The requirement debounce should be set to 10s in E2E (via requirements.debounceSeconds=10
// in Helm values) for tests to complete in reasonable time.
package e2e

import (
	"context"
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
)

// Prometheus Operator GVRs for creating ServiceMonitor/PodMonitor fixtures.
var (
	serviceMonitorGVR = schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors",
	}
)

func TestRequirements(t *testing.T) {
	t.Parallel()

	// PrometheusMonitorMissing verifies that deploying a workload with a metrics port
	// causes a MissingResource constraint to appear in the ConstraintReport and workload
	// annotations after the debounce window.
	t.Run("PrometheusMonitorMissing", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "servicemonitors.monitoring.coreos.com")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy so the reconciler triggers for this namespace.
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-prom-missing")
		t.Cleanup(npCleanup)

		deployName := "metrics-app-" + rand.String(5)
		cleanup := createDeploymentWithMetricsPort(t, sharedDynamicClient, ns, deployName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Wait for the MissingResource entry in the ConstraintReport.
		entry := waitForMissingResource(t, sharedDynamicClient, ns, requirementDetectionTimeout, func(e map[string]interface{}) bool {
			reason, _, _ := unstructured.NestedString(e, "reason")
			return strings.Contains(reason, "metrics") || strings.Contains(reason, "ServiceMonitor")
		})
		require.NotNil(t, entry, "expected missing-resource entry for ServiceMonitor")

		severity, _, _ := unstructured.NestedString(entry, "severity")
		assert.Equal(t, "Warning", severity, "missing ServiceMonitor should be Warning severity")
		t.Logf("Found missing ServiceMonitor entry: severity=%s", severity)

		// Verify the entry contains expected workload reference.
		workloadName, _, _ := unstructured.NestedString(entry, "forWorkload", "name")
		assert.Equal(t, deployName, workloadName, "missingResource should reference the test deployment")
	})

	// PrometheusMonitorResolved verifies that creating a matching ServiceMonitor
	// resolves the missing-resource alert.
	t.Run("PrometheusMonitorResolved", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "servicemonitors.monitoring.coreos.com")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy so the reconciler triggers for this namespace.
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-prom-resolve")
		t.Cleanup(npCleanup)

		deployName := "metrics-resolve-" + rand.String(5)
		cleanup := createDeploymentWithMetricsPort(t, sharedDynamicClient, ns, deployName)
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Phase 1: Wait for the missing-resource alert to appear.
		waitForMissingResource(t, sharedDynamicClient, ns, requirementDetectionTimeout, func(e map[string]interface{}) bool {
			reason, _, _ := unstructured.NestedString(e, "reason")
			return strings.Contains(reason, "metrics") || strings.Contains(reason, "ServiceMonitor")
		})
		t.Log("Phase 1: Missing ServiceMonitor alert appeared")

		// Phase 2: Create a matching ServiceMonitor.
		sm := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "monitoring.coreos.com/v1",
				"kind":       "ServiceMonitor",
				"metadata": map[string]interface{}{
					"name":      "e2e-monitor-" + deployName,
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": deployName,
						},
					},
					"endpoints": []interface{}{
						map[string]interface{}{
							"port": "metrics",
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, sm)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, serviceMonitorGVR, ns, "e2e-monitor-"+deployName)
		})

		// Phase 3: Wait for the alert to be resolved (disappear from missingResources).
		waitForCondition(t, requirementDetectionTimeout, defaultPollInterval, func() (bool, error) {
			obj, err := sharedDynamicClient.Resource(constraintReportGVR).Namespace(ns).Get(
				context.Background(), "constraints", metav1.GetOptions{},
			)
			if err != nil {
				return false, nil
			}
			mr, ok, _ := unstructured.NestedMap(obj.Object, "status", "machineReadable")
			if !ok || mr == nil {
				return true, nil // No machineReadable = no missing resources
			}
			entries, ok, _ := unstructured.NestedSlice(mr, "missingResources")
			if !ok || len(entries) == 0 {
				return true, nil
			}
			// Check if the prometheus-monitor entry is still present.
			for _, raw := range entries {
				entry, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				reason, _, _ := unstructured.NestedString(entry, "reason")
				if strings.Contains(reason, "metrics") || strings.Contains(reason, "ServiceMonitor") {
					return false, nil // still present
				}
			}
			return true, nil
		})
		t.Log("Phase 2: Missing ServiceMonitor alert resolved after creating ServiceMonitor")
	})

	// IstioMTLSMissing verifies that deploying a workload in a namespace with
	// istio-injection=enabled causes a missing-PeerAuthentication alert.
	t.Run("IstioMTLSMissing", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "peerauthentications.security.istio.io")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Add istio-injection=enabled label BEFORE creating the trigger, so the
		// evaluator sees the label on the first reconcile.
		patchNamespaceLabel(t, sharedClientset, ns, "istio-injection", "enabled")

		// Create and wait for the deployment BEFORE the trigger, so that
		// evaluateMissingResources finds the workload on the first reconcile
		// and starts the debounce timer immediately.
		deployName := "istio-app-" + rand.String(5)
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		t.Cleanup(cleanupDep)
		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Create a NetworkPolicy to trigger the reconciler for this namespace.
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-istio-mtls")
		t.Cleanup(npCleanup)

		// Wait for missing-PeerAuthentication alert.
		entry := waitForMissingResource(t, sharedDynamicClient, ns, requirementDetectionTimeout, func(e map[string]interface{}) bool {
			kind, _, _ := unstructured.NestedString(e, "expectedKind")
			return kind == "PeerAuthentication"
		})
		require.NotNil(t, entry, "expected missing-PeerAuthentication entry")

		severity, _, _ := unstructured.NestedString(entry, "severity")
		assert.Equal(t, "Warning", severity, "missing PeerAuthentication should be Warning severity")
		t.Logf("Found missing PeerAuthentication entry: severity=%s", severity)
	})

	// CertIssuerMissing verifies that deploying a workload with a cert-manager
	// annotation referencing a non-existent ClusterIssuer causes a Critical alert.
	t.Run("CertIssuerMissing", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "clusterissuers.cert-manager.io")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy so the reconciler triggers for this namespace.
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cert-issuer")
		t.Cleanup(npCleanup)

		deployName := "cert-app-" + rand.String(5)
		cleanup := createDeploymentWithAnnotations(t, sharedDynamicClient, ns, deployName, map[string]interface{}{
			"cert-manager.io/cluster-issuer": "e2e-nonexistent-issuer",
		})
		t.Cleanup(cleanup)
		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Wait for missing-ClusterIssuer alert.
		entry := waitForMissingResource(t, sharedDynamicClient, ns, requirementDetectionTimeout, func(e map[string]interface{}) bool {
			reason, _, _ := unstructured.NestedString(e, "reason")
			return strings.Contains(reason, "ClusterIssuer") || strings.Contains(reason, "e2e-nonexistent-issuer")
		})
		require.NotNil(t, entry, "expected missing-ClusterIssuer entry")

		severity, _, _ := unstructured.NestedString(entry, "severity")
		assert.Equal(t, "Critical", severity, "missing ClusterIssuer should be Critical severity")
		t.Logf("Found missing ClusterIssuer entry: severity=%s", severity)
	})

	// MissingCRDDetection verifies that when a workload references functionality
	// from a CRD that is not installed, a "CRD not installed" alert fires.
	// Uses the cert-manager.io/cluster-issuer annotation on a workload when
	// cert-manager CRDs are NOT installed.
	t.Run("MissingCRDDetection", func(t *testing.T) {
		t.Parallel()

		// This test requires that at least one CRD is NOT installed.
		// We use a synthetic approach: check if cert-manager, Istio, or Prometheus CRDs
		// are absent, and test with whichever is missing.
		type crdTestCase struct {
			crdName     string
			setupFn     func(t *testing.T, dynamicClient dynamic.Interface, ns, name string) func()
			matchReason string
		}

		cases := []crdTestCase{
			{
				crdName: "clusterissuers.cert-manager.io",
				setupFn: func(t *testing.T, dc dynamic.Interface, ns, name string) func() {
					return createDeploymentWithAnnotations(t, dc, ns, name, map[string]interface{}{
						"cert-manager.io/cluster-issuer": "nonexistent",
					})
				},
				matchReason: "clusterissuers.cert-manager.io",
			},
			{
				crdName: "peerauthentications.security.istio.io",
				setupFn: func(t *testing.T, dc dynamic.Interface, ns, name string) func() {
					return createDeploymentWithAnnotations(t, dc, ns, name, map[string]interface{}{
						"sidecar.istio.io/status": "injected",
					})
				},
				matchReason: "peerauthentications.security.istio.io",
			},
		}

		tested := false
		for _, tc := range cases {
			tc := tc
			// Check if CRD is NOT installed.
			_, err := sharedDynamicClient.Resource(crdGVR).Get(
				context.Background(), tc.crdName, metav1.GetOptions{},
			)
			if err == nil {
				continue // CRD is installed, try next
			}

			// Found a missing CRD — run the test.
			ns, cleanupNS := createTestNamespace(t, sharedClientset)
			t.Cleanup(cleanupNS)

			// Create a NetworkPolicy so the reconciler triggers for this namespace.
			npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-crd-detect")
			t.Cleanup(npCleanup)

			deployName := "crd-detect-" + rand.String(5)
			cleanup := tc.setupFn(t, sharedDynamicClient, ns, deployName)
			t.Cleanup(cleanup)
			waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

			// Wait for the "CRD not installed" alert.
			entry := waitForMissingResource(t, sharedDynamicClient, ns, requirementDetectionTimeout, func(e map[string]interface{}) bool {
				reason, _, _ := unstructured.NestedString(e, "reason")
				return strings.Contains(reason, "not installed") && strings.Contains(reason, tc.matchReason)
			})
			require.NotNil(t, entry, "expected 'CRD not installed' entry for %s", tc.crdName)
			t.Logf("Found missing CRD detection entry for %s", tc.crdName)
			tested = true
			break
		}

		if !tested {
			t.Skip("Skipping: all tested CRDs (cert-manager, Istio) are installed; no missing CRD to detect")
		}
	})

	// DebounceNoFalsePositive verifies that when a ServiceMonitor is created
	// before the debounce window expires, no missing-resource alert fires.
	t.Run("DebounceNoFalsePositive", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "servicemonitors.monitoring.coreos.com")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy as a baseline trigger so the ConstraintReport
		// gets created for this namespace (proving the reconciler has run).
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-debounce-fp")
		t.Cleanup(npCleanup)

		deployName := "debounce-fp-" + rand.String(5)
		cleanup := createDeploymentWithMetricsPort(t, sharedDynamicClient, ns, deployName)
		t.Cleanup(cleanup)

		// Immediately create a matching ServiceMonitor (before debounce window).
		sm := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "monitoring.coreos.com/v1",
				"kind":       "ServiceMonitor",
				"metadata": map[string]interface{}{
					"name":      "e2e-monitor-" + deployName,
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": deployName,
						},
					},
					"endpoints": []interface{}{
						map[string]interface{}{
							"port": "metrics",
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, sm)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, serviceMonitorGVR, ns, "e2e-monitor-"+deployName)
		})

		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Wait for the baseline NetworkPolicy constraint to appear in the report
		// (proves the ConstraintReport has been created and the reconciler is active).
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			return statusInt64(status, "constraintCount") >= 1
		})
		t.Log("Baseline constraint appeared in ConstraintReport")

		// Verify no missing-resource entry appears for 30s (well past the 10s debounce).
		waitForNoMissingResource(t, sharedDynamicClient, ns, 30*time.Second, func(e map[string]interface{}) bool {
			reason, _, _ := unstructured.NestedString(e, "reason")
			return strings.Contains(reason, "metrics") || strings.Contains(reason, "ServiceMonitor")
		})
		t.Log("Confirmed: no false-positive missing-ServiceMonitor alert")
	})

	// DebounceDeleteRecreate verifies that deleting and immediately recreating
	// a required resource does not cause a false-positive alert.
	t.Run("DebounceDeleteRecreate", func(t *testing.T) {
		t.Parallel()
		requireCRDInstalled(t, sharedDynamicClient, "servicemonitors.monitoring.coreos.com")

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy baseline trigger.
		npCleanup := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-debounce-dr")
		t.Cleanup(npCleanup)

		deployName := "debounce-dr-" + rand.String(5)
		cleanup := createDeploymentWithMetricsPort(t, sharedDynamicClient, ns, deployName)
		t.Cleanup(cleanup)

		smName := "e2e-monitor-" + deployName
		smObj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "monitoring.coreos.com/v1",
				"kind":       "ServiceMonitor",
				"metadata": map[string]interface{}{
					"name":      smName,
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": deployName,
						},
					},
					"endpoints": []interface{}{
						map[string]interface{}{
							"port": "metrics",
						},
					},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, smObj)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, serviceMonitorGVR, ns, smName)
		})

		waitForDeploymentReady(t, sharedClientset, ns, deployName, defaultTimeout)

		// Wait for the baseline to be established (no missing resources).
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			return statusInt64(status, "constraintCount") >= 1
		})
		t.Log("Baseline established with ServiceMonitor present")

		// Delete the ServiceMonitor.
		deleteUnstructured(t, sharedDynamicClient, serviceMonitorGVR, ns, smName)
		t.Log("Deleted ServiceMonitor")

		// Immediately recreate it (well within the 10s debounce window).
		applyUnstructured(t, sharedDynamicClient, smObj)
		t.Log("Recreated ServiceMonitor")

		// Verify no missing-resource alert fires for 30s (3x the debounce window).
		waitForNoMissingResource(t, sharedDynamicClient, ns, 30*time.Second, func(e map[string]interface{}) bool {
			reason, _, _ := unstructured.NestedString(e, "reason")
			return strings.Contains(reason, "metrics") || strings.Contains(reason, "ServiceMonitor")
		})
		t.Log("Confirmed: no false-positive alert after delete-recreate cycle")
	})
}
