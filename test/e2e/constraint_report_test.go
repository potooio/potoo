//go:build e2e
// +build e2e

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
	"k8s.io/client-go/dynamic"
)

// constraintReportGVR is the GVR for the ConstraintReport CRD.
var constraintReportGVR = schema.GroupVersionResource{
	Group:    "potoo.io",
	Version:  "v1alpha1",
	Resource: "constraintreports",
}

// reportCreateTimeout is the time to wait for a ConstraintReport to be created.
// Accounts for: informer sync + adapter parse + indexer upsert + debounce (10s) + ticker (5s) + reconcile.
// Use 180s: under full parallel load on single-node clusters (Docker Desktop), all 7
// test groups compete for controller cycles, making 120s marginal.
const reportCreateTimeout = 180 * time.Second

// reportUpdateTimeout is the time to wait for a ConstraintReport to update after a change.
// Accounts for debounce re-queue + ticker + reconcile under CI load.
const reportUpdateTimeout = 60 * time.Second

// getConstraintReport polls for the ConstraintReport named "constraints" in the
// given namespace and returns it once found.
func getConstraintReport(t *testing.T, dynClient dynamic.Interface, namespace string, timeout time.Duration) *unstructured.Unstructured {
	t.Helper()
	var report *unstructured.Unstructured

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		obj, err := dynClient.Resource(constraintReportGVR).Namespace(namespace).Get(
			context.Background(), "constraints", metav1.GetOptions{},
		)
		if err != nil {
			return false, nil // not found yet
		}
		report = obj
		return true, nil
	})
	return report
}

// getReportStatus extracts the .status map from a ConstraintReport.
// Returns nil if status is not set.
func getReportStatus(report *unstructured.Unstructured) map[string]interface{} {
	if report == nil {
		return nil
	}
	status, ok, _ := unstructured.NestedMap(report.Object, "status")
	if !ok {
		return nil
	}
	return status
}

// waitForReportCondition polls the ConstraintReport in the given namespace until
// condFn returns true for the report's status, or the timeout expires.
func waitForReportCondition(t *testing.T, dynClient dynamic.Interface, namespace string, timeout time.Duration, condFn func(status map[string]interface{}) bool) {
	t.Helper()
	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		obj, err := dynClient.Resource(constraintReportGVR).Namespace(namespace).Get(
			context.Background(), "constraints", metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		status := getReportStatus(obj)
		if status == nil {
			return false, nil
		}
		return condFn(status), nil
	})
}

// statusInt64 safely extracts an int64 from a status map field.
func statusInt64(status map[string]interface{}, key string) int64 {
	val, ok, _ := unstructured.NestedInt64(status, key)
	if !ok {
		return 0
	}
	return val
}

// statusConstraintNames extracts the list of constraint names from
// status.constraints[].name.
func statusConstraintNames(status map[string]interface{}) []string {
	entries, ok, _ := unstructured.NestedSlice(status, "constraints")
	if !ok {
		return nil
	}
	var names []string
	for _, entry := range entries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok, _ := unstructured.NestedString(e, "name")
		if ok {
			names = append(names, name)
		}
	}
	return names
}

// statusConstraintSources extracts the list of constraint sources from
// status.constraints[].source.
func statusConstraintSources(status map[string]interface{}) []string {
	entries, ok, _ := unstructured.NestedSlice(status, "constraints")
	if !ok {
		return nil
	}
	var sources []string
	for _, entry := range entries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		source, ok, _ := unstructured.NestedString(e, "source")
		if ok {
			sources = append(sources, source)
		}
	}
	return sources
}

// severityOrderValue returns a numeric sort order for severity strings.
func severityOrderValue(severity string) int {
	switch severity {
	case "Critical":
		return 0
	case "Warning":
		return 1
	case "Info":
		return 2
	default:
		return 3
	}
}

func TestConstraintReport(t *testing.T) {
	t.Parallel()

	// CreatedOnConstraint verifies that creating a NetworkPolicy
	// in the test namespace causes a ConstraintReport to be created with correct
	// constraint counts and a populated machineReadable section.
	t.Run("CreatedOnConstraint", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		// Create a default-deny-ingress NetworkPolicy.
		npGVR := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-report-deny-ingress",
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(ns).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create NetworkPolicy")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(npGVR).Namespace(ns).Delete(ctx, "e2e-report-deny-ingress", metav1.DeleteOptions{})
		})

		// Wait for ConstraintReport to appear with at least 1 constraint.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			return statusInt64(status, "constraintCount") >= 1
		})

		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status, "ConstraintReport status should be set")

		constraintCount := statusInt64(status, "constraintCount")
		assert.GreaterOrEqual(t, constraintCount, int64(1), "constraintCount should be >= 1")

		// Severity counts should be non-negative.
		assert.GreaterOrEqual(t, statusInt64(status, "criticalCount"), int64(0))
		assert.GreaterOrEqual(t, statusInt64(status, "warningCount"), int64(0))
		assert.GreaterOrEqual(t, statusInt64(status, "infoCount"), int64(0))

		// Constraints list should be non-empty.
		entries, ok, _ := unstructured.NestedSlice(status, "constraints")
		assert.True(t, ok, "status.constraints should exist")
		assert.NotEmpty(t, entries, "status.constraints should be non-empty")

		// MachineReadable should be populated.
		mr, ok, _ := unstructured.NestedMap(status, "machineReadable")
		require.True(t, ok, "status.machineReadable should exist")
		require.NotNil(t, mr, "machineReadable should not be nil")

		sv, _, _ := unstructured.NestedString(mr, "schemaVersion")
		assert.Equal(t, "1", sv, "schemaVersion should be '1'")

		mrConstraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
		assert.True(t, ok, "machineReadable.constraints should exist")
		assert.GreaterOrEqual(t, int64(len(mrConstraints)), constraintCount,
			"machineReadable.constraints length should match constraintCount")

		t.Logf("ConstraintReport created: %d constraints", constraintCount)
	})

	// UpdateOnConstraintChange verifies that updating a
	// constraint (ResourceQuota) causes the ConstraintReport to be re-reconciled.
	t.Run("UpdateOnConstraintChange", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		rqGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"}

		// Create a ResourceQuota.
		rq := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ResourceQuota",
				"metadata": map[string]interface{}{
					"name":      "e2e-report-quota",
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"hard": map[string]interface{}{
						"cpu":    "10",
						"memory": "10Gi",
					},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(rqGVR).Namespace(ns).Create(ctx, rq, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create ResourceQuota")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(rqGVR).Namespace(ns).Delete(ctx, "e2e-report-quota", metav1.DeleteOptions{})
		})

		// Wait for the report to include the ResourceQuota constraint.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			sources := statusConstraintSources(status)
			for _, src := range sources {
				if src == "resourcequotas" {
					return true
				}
			}
			return false
		})

		// Record the lastUpdated timestamp.
		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status)
		lastUpdated, _, _ := unstructured.NestedString(status, "lastUpdated")
		require.NotEmpty(t, lastUpdated, "lastUpdated should be set")
		t.Logf("Initial lastUpdated: %s", lastUpdated)

		// Update the ResourceQuota (change the cpu hard limit).
		rqObj, err := sharedDynamicClient.Resource(rqGVR).Namespace(ns).Get(ctx, "e2e-report-quota", metav1.GetOptions{})
		require.NoError(t, err)
		err = unstructured.SetNestedField(rqObj.Object, "5", "spec", "hard", "cpu")
		require.NoError(t, err)
		_, err = sharedDynamicClient.Resource(rqGVR).Namespace(ns).Update(ctx, rqObj, metav1.UpdateOptions{})
		require.NoError(t, err, "failed to update ResourceQuota")

		// Wait for lastUpdated to change (report was re-reconciled).
		waitForReportCondition(t, sharedDynamicClient, ns, reportUpdateTimeout, func(status map[string]interface{}) bool {
			newLastUpdated, _, _ := unstructured.NestedString(status, "lastUpdated")
			return newLastUpdated != "" && newLastUpdated != lastUpdated
		})

		// Verify the ResourceQuota is still in the report.
		report = getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status = getReportStatus(report)
		sources := statusConstraintSources(status)
		found := false
		for _, src := range sources {
			if src == "resourcequotas" {
				found = true
				break
			}
		}
		assert.True(t, found, "ResourceQuota should still be in the report after update")

		t.Logf("ConstraintReport updated after ResourceQuota change")
	})

	// DeleteConstraint verifies that deleting a constraint
	// removes it from the ConstraintReport.
	t.Run("DeleteConstraint", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		npGVR := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
		npName := "e2e-report-delete-test"

		// Create a NetworkPolicy.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      npName,
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"protocol": "TCP",
									"port":     int64(443),
								},
							},
						},
					},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(ns).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create NetworkPolicy for delete test")
		t.Cleanup(func() {
			// Best-effort cleanup in case the test fails before the manual delete.
			_ = sharedDynamicClient.Resource(npGVR).Namespace(ns).Delete(ctx, npName, metav1.DeleteOptions{})
		})

		// Wait for the constraint to appear in the report (by name).
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if n == npName {
					return true
				}
			}
			return false
		})
		t.Log("NetworkPolicy constraint appeared in report")

		// Delete the NetworkPolicy.
		err = sharedDynamicClient.Resource(npGVR).Namespace(ns).Delete(ctx, npName, metav1.DeleteOptions{})
		require.NoError(t, err, "failed to delete NetworkPolicy")

		// Wait for the constraint to be removed from the report (by name).
		waitForReportCondition(t, sharedDynamicClient, ns, reportUpdateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if n == npName {
					return false // still present
				}
			}
			return true // gone
		})

		t.Log("Deleted constraint removed from ConstraintReport")
	})

	// MachineReadable verifies the machineReadable section of
	// the ConstraintReport contains structured data with all expected fields.
	t.Run("MachineReadable", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		// Create a NetworkPolicy with ingress rules.
		npGVR := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-report-mr-test",
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
					"ingress": []interface{}{
						map[string]interface{}{
							"from": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{
											"app": "frontend",
										},
									},
								},
							},
							"ports": []interface{}{
								map[string]interface{}{
									"protocol": "TCP",
									"port":     int64(8080),
								},
							},
						},
					},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(ns).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create NetworkPolicy for machine-readable test")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(npGVR).Namespace(ns).Delete(ctx, "e2e-report-mr-test", metav1.DeleteOptions{})
		})

		// Wait for the machineReadable section to be populated.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			mr, ok, _ := unstructured.NestedMap(status, "machineReadable")
			if !ok || mr == nil {
				return false
			}
			constraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
			return ok && len(constraints) > 0
		})

		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status)

		mr, ok, _ := unstructured.NestedMap(status, "machineReadable")
		require.True(t, ok, "machineReadable should exist")

		// Verify top-level machineReadable fields.
		sv, _, _ := unstructured.NestedString(mr, "schemaVersion")
		assert.Equal(t, "1", sv, "schemaVersion should be '1'")

		dl, _, _ := unstructured.NestedString(mr, "detailLevel")
		assert.NotEmpty(t, dl, "detailLevel should be set")

		ga, _, _ := unstructured.NestedString(mr, "generatedAt")
		assert.NotEmpty(t, ga, "generatedAt should be set")

		// Verify at least one machine constraint entry has required fields.
		constraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
		require.True(t, ok && len(constraints) > 0, "machineReadable.constraints should be non-empty")

		entry, ok := constraints[0].(map[string]interface{})
		require.True(t, ok, "constraint entry should be a map")

		uid, _, _ := unstructured.NestedString(entry, "uid")
		assert.NotEmpty(t, uid, "uid should be set")

		name, _, _ := unstructured.NestedString(entry, "name")
		assert.NotEmpty(t, name, "name should be set")

		ct, _, _ := unstructured.NestedString(entry, "constraintType")
		assert.NotEmpty(t, ct, "constraintType should be set")

		sev, _, _ := unstructured.NestedString(entry, "severity")
		assert.NotEmpty(t, sev, "severity should be set")

		// Verify sourceRef is populated.
		sourceRef, ok, _ := unstructured.NestedMap(entry, "sourceRef")
		if assert.True(t, ok, "sourceRef should exist") {
			apiVersion, _, _ := unstructured.NestedString(sourceRef, "apiVersion")
			assert.NotEmpty(t, apiVersion, "sourceRef.apiVersion should be set")

			kind, _, _ := unstructured.NestedString(sourceRef, "kind")
			assert.NotEmpty(t, kind, "sourceRef.kind should be set")
		}

		// Verify remediation is present.
		remediation, ok, _ := unstructured.NestedMap(entry, "remediation")
		if assert.True(t, ok, "remediation should exist") {
			summary, _, _ := unstructured.NestedString(remediation, "summary")
			assert.NotEmpty(t, summary, "remediation.summary should be set")
		}

		t.Logf("MachineReadable section validated: %d constraint entries", len(constraints))
	})

	// SeverityCounts verifies that the ConstraintReport
	// correctly counts constraints by severity level.
	t.Run("SeverityCounts", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		npGVR := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
		rqGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"}

		// Create a NetworkPolicy (produces Warning severity).
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "e2e-report-severity-np",
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(ns).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create NetworkPolicy for severity test")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(npGVR).Namespace(ns).Delete(ctx, "e2e-report-severity-np", metav1.DeleteOptions{})
		})

		// Create a ResourceQuota (produces Info severity with used=0).
		rq := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ResourceQuota",
				"metadata": map[string]interface{}{
					"name":      "e2e-report-severity-rq",
					"namespace": ns,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"hard": map[string]interface{}{
						"pods": "100",
					},
				},
			},
		}
		_, err = sharedDynamicClient.Resource(rqGVR).Namespace(ns).Create(ctx, rq, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create ResourceQuota for severity test")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(rqGVR).Namespace(ns).Delete(ctx, "e2e-report-severity-rq", metav1.DeleteOptions{})
		})

		// Wait for the report to include both constraints (by source).
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			sources := statusConstraintSources(status)
			hasNP := false
			hasRQ := false
			for _, src := range sources {
				if src == "networkpolicies" {
					hasNP = true
				}
				if src == "resourcequotas" {
					hasRQ = true
				}
			}
			return hasNP && hasRQ
		})

		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status)

		constraintCount := statusInt64(status, "constraintCount")
		warningCount := statusInt64(status, "warningCount")
		infoCount := statusInt64(status, "infoCount")

		assert.GreaterOrEqual(t, constraintCount, int64(2), "constraintCount should be >= 2")
		assert.GreaterOrEqual(t, warningCount, int64(1), "warningCount should be >= 1 (NetworkPolicy)")
		assert.GreaterOrEqual(t, infoCount, int64(1), "infoCount should be >= 1 (ResourceQuota)")

		// Verify severity sum is consistent.
		criticalCount := statusInt64(status, "criticalCount")
		severitySum := criticalCount + warningCount + infoCount
		assert.Equal(t, constraintCount, severitySum,
			"severity counts should sum to constraintCount")

		// Verify constraints are sorted by severity (Critical first, then Warning, then Info).
		entries, ok, _ := unstructured.NestedSlice(status, "constraints")
		if ok && len(entries) > 1 {
			prevOrder := -1
			for _, entry := range entries {
				e, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				sev, _, _ := unstructured.NestedString(e, "severity")
				order := severityOrderValue(sev)
				assert.GreaterOrEqual(t, order, prevOrder,
					"constraints should be sorted by severity; found %s after lower severity", sev)
				prevOrder = order
			}
		}

		t.Logf("Severity counts: critical=%d warning=%d info=%d total=%d",
			criticalCount, warningCount, infoCount, constraintCount)
	})

	// ClusterScopedConstraint verifies that a cluster-scoped
	// constraint (ValidatingWebhookConfiguration) appears in the ConstraintReport
	// for the test namespace.
	t.Run("ClusterScopedConstraint", func(t *testing.T) {
		t.Parallel()
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)
		ctx := context.Background()

		// Use a distinct name to avoid collision with cluster_scoped_test.go.
		webhookName := fmt.Sprintf("e2e-report-webhook-%s", ns)
		vwhcGVR := schema.GroupVersionResource{
			Group:    "admissionregistration.k8s.io",
			Version:  "v1",
			Resource: "validatingwebhookconfigurations",
		}

		webhook := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "admissionregistration.k8s.io/v1",
				"kind":       "ValidatingWebhookConfiguration",
				"metadata": map[string]interface{}{
					"name": webhookName,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"webhooks": []interface{}{
					map[string]interface{}{
						"name":                    "e2e-report.example.io",
						"admissionReviewVersions": []interface{}{"v1"},
						"sideEffects":             "None",
						"failurePolicy":           "Ignore",
						"clientConfig": map[string]interface{}{
							"url": "https://localhost:9443/validate-report",
						},
						"rules": []interface{}{
							map[string]interface{}{
								"apiGroups":   []interface{}{""},
								"apiVersions": []interface{}{"v1"},
								"operations":  []interface{}{"CREATE"},
								"resources":   []interface{}{"configmaps"},
							},
						},
					},
				},
			},
		}

		// Create directly using GVR (cluster-scoped, not via applyUnstructured).
		_, err := sharedDynamicClient.Resource(vwhcGVR).Create(ctx, webhook, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create ValidatingWebhookConfiguration")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(vwhcGVR).Delete(ctx, webhookName, metav1.DeleteOptions{})
		})
		t.Log("Created cluster-scoped ValidatingWebhookConfiguration")

		// Wait for the constraint to appear in the test namespace's report.
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			sources := statusConstraintSources(status)
			for _, src := range sources {
				if src == "validatingwebhookconfigurations" {
					return true
				}
			}
			return false
		})

		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status)

		// Verify the webhook constraint appears.
		sources := statusConstraintSources(status)
		found := false
		for _, src := range sources {
			if src == "validatingwebhookconfigurations" {
				found = true
				break
			}
		}
		assert.True(t, found, "cluster-scoped webhook should appear in namespace report")

		// Verify in machineReadable as well.
		mr, ok, _ := unstructured.NestedMap(status, "machineReadable")
		if ok && mr != nil {
			mrConstraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
			if ok {
				mrFound := false
				for _, c := range mrConstraints {
					entry, ok := c.(map[string]interface{})
					if !ok {
						continue
					}
					sourceRef, ok, _ := unstructured.NestedMap(entry, "sourceRef")
					if !ok {
						continue
					}
					kind, _, _ := unstructured.NestedString(sourceRef, "kind")
					if kind == "ValidatingWebhookConfiguration" {
						mrFound = true
						break
					}
				}
				assert.True(t, mrFound,
					"cluster-scoped webhook should appear in machineReadable.constraints")
			}
		}

		t.Logf("Cluster-scoped constraint appeared in namespace %s report", ns)
	})
}
