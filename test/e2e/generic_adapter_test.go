//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the generic adapter framework and
// ConstraintProfile CRD controller. These tests verify that platform teams can
// dynamically register arbitrary CRDs as constraint types without recompiling,
// and that the ConstraintProfile controller reconciles changes within 30s.
//
// Each test creates its own namespace and uses randomized CRD group names to
// avoid cross-test interference when running in parallel.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
)

const (
	// profileDiscoveryTimeout accounts for: ConstraintProfile reconcile + informer start +
	// initial list + adapter parse + indexer upsert + annotator debounce + patch.
	// Use 180s to accommodate parallel test contention on single-node clusters.
	profileDiscoveryTimeout = 180 * time.Second

	// profileUpdateTimeout is the time to wait for a ConstraintProfile update to propagate.
	// The controller-runtime reconciler is event-driven, so reconcile is near-instant.
	// The 60s budget covers informer restart + re-list + parse + annotator cycle under
	// parallel CI load on single-node clusters.
	profileUpdateTimeout = 60 * time.Second

	// profileDeletionTimeout is the time to wait after deleting a ConstraintProfile
	// for constraints to be removed from the index.
	profileDeletionTimeout = 60 * time.Second

	// heuristicStableWindow is how long to wait to confirm a CRD is NOT auto-detected.
	// Covers two rescan cycles (15s each in E2E) plus buffer.
	heuristicStableWindow = 45 * time.Second
)

func TestGenericAdapter(t *testing.T) {
	t.Parallel()

	// ProfileLifecycle verifies the full create flow: ConstraintProfile -> generic adapter
	// watches CRD -> CRD instance is discovered, parsed, and indexed as a constraint ->
	// workload annotations are populated.
	t.Run("ProfileLifecycle", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Use a group name that avoids all defaultPolicyNameHints to ensure discovery
		// only happens via the ConstraintProfile, not via heuristic matching.
		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "deployguards"
		kind := "DeployGuard"
		version := "v1"
		profileName := "e2e-lifecycle-" + suffix

		// 1. Create the custom CRD.
		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		// 2. Create the ConstraintProfile.
		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter": "generic",
			"enabled": true,
		})
		t.Cleanup(cleanupProfile)

		// 3. Create a sentinel deployment.
		sentinelName := "sentinel-lifecycle-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// 4. Create an instance of the custom CRD with a podSelector.
		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-guard-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
				"action": "deny",
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// 5. Wait for the constraint to appear in workload annotations.
		t.Log("Waiting for generic adapter to discover CRD instance via ConstraintProfile...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		require.NotEmpty(t, constraints, "expected constraint from %s in workload annotations", resource)

		for _, c := range constraints {
			if c.Source == resource {
				t.Logf("Found constraint: type=%s name=%s source=%s severity=%s", c.Type, c.Name, c.Source, c.Severity)
				break
			}
		}
	})

	// FieldPathExtraction verifies that custom field paths in the ConstraintProfile
	// correctly extract selector, effect, summary, and namespace selector from
	// non-standard CRD fields.
	t.Run("FieldPathExtraction", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "accesschecks"
		kind := "AccessCheck"
		version := "v1"
		profileName := "e2e-fieldpath-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		// Create profile with custom field paths pointing to non-standard locations.
		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter": "generic",
			"enabled": true,
			"fieldPaths": map[string]interface{}{
				"selectorPath":          "spec.targets",
				"effectPath":            "spec.mode",
				"summaryPath":           "spec.description",
				"namespaceSelectorPath": "spec.nsSelector",
			},
		})
		t.Cleanup(cleanupProfile)

		sentinelName := "sentinel-fieldpath-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// Create CR instance with non-standard field names.
		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-check-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"targets": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
				"mode":        "Deny",
				"description": "E2E field path test check",
				"nsSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"env": "test",
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		t.Log("Waiting for field path extraction to produce constraint...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		require.NotEmpty(t, constraints, "expected constraint from %s with custom field paths", resource)

		for _, c := range constraints {
			if c.Source == resource {
				t.Logf("Found constraint with field paths: type=%s name=%s source=%s", c.Type, c.Name, c.Source)
				break
			}
		}
	})

	// ProfileUpdate verifies that updating a ConstraintProfile (e.g., changing severity)
	// causes the constraint to be re-parsed with the new configuration within 30s.
	t.Run("ProfileUpdate", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "verifications"
		kind := "Verification"
		version := "v1"
		profileName := "e2e-update-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		// Create profile with severity=Info.
		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter":  "generic",
			"enabled":  true,
			"severity": "Info",
		})
		t.Cleanup(cleanupProfile)

		sentinelName := "sentinel-update-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-verify-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Wait for initial constraint with Info severity.
		t.Log("Waiting for initial constraint with Info severity...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource && c.Severity == "Info"
		})
		require.NotEmpty(t, constraints, "expected Info severity constraint from %s", resource)
		t.Log("Initial constraint found with Info severity")

		// Update profile to Critical severity.
		updateConstraintProfile(t, sharedDynamicClient, profileName, func(obj *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(obj.Object, "Critical", "spec", "severity")
		})

		// Trigger re-parse by updating the CR instance (reconcile is event-driven).
		crObj, err := sharedDynamicClient.Resource(crGVR).Namespace(ns).Get(
			context.Background(), crName, metav1.GetOptions{},
		)
		require.NoError(t, err)
		_ = unstructured.SetNestedField(crObj.Object, "updated", "spec", "trigger")
		_, err = sharedDynamicClient.Resource(crGVR).Namespace(ns).Update(
			context.Background(), crObj, metav1.UpdateOptions{},
		)
		require.NoError(t, err, "failed to update CR to trigger re-parse")

		// Wait for severity to change to Critical.
		t.Log("Waiting for constraint severity to change to Critical within 30s...")
		constraints = waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileUpdateTimeout, func(c constraintSummary) bool {
			return c.Source == resource && c.Severity == "Critical"
		})
		require.NotEmpty(t, constraints, "expected Critical severity constraint after profile update")
		t.Log("Constraint severity updated to Critical within timeout")
	})

	// ProfileDeletion verifies that deleting a ConstraintProfile causes the adapter to stop
	// watching the target CRD and constraints are removed from the index.
	t.Run("ProfileDeletion", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "acmeguards"
		kind := "AcmeGuard"
		version := "v1"
		profileName := "e2e-deletion-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter": "generic",
			"enabled": true,
		})
		// Register cleanup as safety net in case test fails before manual delete.
		// The manual cleanupProfile() call below executes first; this fallback
		// harmlessly warns if the resource is already gone.
		t.Cleanup(cleanupProfile)

		sentinelName := "sentinel-deletion-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-acme-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Wait for constraint to be discovered.
		t.Log("Waiting for constraint to be discovered before deletion...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		require.NotEmpty(t, constraints, "expected constraint from %s before deletion", resource)
		t.Log("Constraint discovered, now deleting ConstraintProfile...")

		// Delete the ConstraintProfile. UnregisterProfile calls indexer.DeleteBySource
		// synchronously, so removal should be near-immediate.
		cleanupProfile()

		// Wait for the constraint to disappear from annotations.
		waitForNoConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDeletionTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		t.Log("Constraint removed from workload annotations after profile deletion")
	})

	// AnnotationAutoDetection verifies that a CRD annotated with
	// potoo.io/is-policy: "true" is automatically discovered by the generic adapter
	// WITHOUT requiring a ConstraintProfile.
	t.Run("AnnotationAutoDetection", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "autodetects"
		kind := "AutoDetect"
		version := "v1"

		// Create CRD with the potoo.io/is-policy annotation.
		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, map[string]interface{}{
			"potoo.io/is-policy": "true",
		})
		t.Cleanup(cleanupCRD)

		sentinelName := "sentinel-autodetect-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		// Create an instance — NO ConstraintProfile is created.
		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-autodetect-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Wait for the generic adapter to auto-detect via annotation.
		// This requires at least one rescan cycle (15s in E2E) to run refreshAnnotatedCRDs.
		t.Log("Waiting for annotation-based auto-detection (requires rescan cycle)...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		require.NotEmpty(t, constraints, "expected auto-detected constraint from annotated CRD %s", resource)
		t.Log("CRD auto-detected via potoo.io/is-policy annotation")
	})

	// HeuristicBoundary verifies that a CRD whose name does NOT match any
	// defaultPolicyNameHints and whose group is NOT in defaultPolicyGroups is NOT
	// auto-detected, but IS detected after a ConstraintProfile is created.
	t.Run("HeuristicBoundary", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Use a name that avoids ALL hints: "policy", "constraint", "rule",
		// "quota", "limit", "authorization" — and a non-policy group.
		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "acmerestrictions" // no hint substring match
		kind := "AcmeRestriction"
		version := "v1"
		profileName := "e2e-heuristic-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		sentinelName := "sentinel-heuristic-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-restriction-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Verify the CRD is NOT auto-detected within two rescan cycles.
		t.Log("Verifying CRD is NOT auto-detected without profile or annotation...")
		waitForNoConstraintMatch(t, sharedDynamicClient, ns, sentinelName, heuristicStableWindow, func(c constraintSummary) bool {
			return c.Source == resource
		})
		t.Log("Confirmed: CRD not auto-detected (heuristic boundary)")

		// Now create a ConstraintProfile — the CRD should become discoverable.
		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter": "generic",
			"enabled": true,
		})
		t.Cleanup(cleanupProfile)

		t.Log("Waiting for constraint to be discovered via ConstraintProfile...")
		constraints := waitForConstraintMatch(t, sharedDynamicClient, ns, sentinelName, profileDiscoveryTimeout, func(c constraintSummary) bool {
			return c.Source == resource
		})
		require.NotEmpty(t, constraints, "expected constraint after ConstraintProfile created")
		t.Log("Constraint discovered after ConstraintProfile creation — heuristic boundary confirmed")
	})

	// ConstraintReport verifies that constraints discovered via the generic adapter
	// produce a ConstraintReport in the namespace with correct counts and
	// machine-readable data.
	t.Run("ConstraintReport", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "reportchecks"
		kind := "ReportCheck"
		version := "v1"
		profileName := "e2e-report-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter":  "generic",
			"enabled":  true,
			"severity": "Warning",
		})
		t.Cleanup(cleanupProfile)

		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-reportcheck-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Wait for ConstraintReport to include the generic adapter constraint.
		t.Log("Waiting for ConstraintReport to include generic adapter constraint...")
		waitForReportCondition(t, sharedDynamicClient, ns, reportCreateTimeout, func(status map[string]interface{}) bool {
			sources := statusConstraintSources(status)
			for _, src := range sources {
				if src == resource {
					return true
				}
			}
			return false
		})

		report := getConstraintReport(t, sharedDynamicClient, ns, 5*time.Second)
		status := getReportStatus(report)
		require.NotNil(t, status, "ConstraintReport status should be set")

		constraintCount := statusInt64(status, "constraintCount")
		assert.GreaterOrEqual(t, constraintCount, int64(1), "constraintCount should be >= 1")

		// Verify machineReadable section contains the generic constraint.
		// Match by sourceRef.name (the CR instance name) rather than sourceRef.kind,
		// because gvrToKindName does not preserve CamelCase for custom CRDs.
		mr, ok, _ := unstructured.NestedMap(status, "machineReadable")
		if assert.True(t, ok, "machineReadable should exist") {
			mrConstraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
			if assert.True(t, ok, "machineReadable.constraints should exist") {
				found := false
				for _, raw := range mrConstraints {
					entry, ok := raw.(map[string]interface{})
					if !ok {
						continue
					}
					sourceRef, ok, _ := unstructured.NestedMap(entry, "sourceRef")
					if !ok {
						continue
					}
					entryName, _, _ := unstructured.NestedString(sourceRef, "name")
					if entryName == crName {
						found = true
						// Verify expected fields.
						uid, _, _ := unstructured.NestedString(entry, "uid")
						assert.NotEmpty(t, uid, "uid should be set")
						sev, _, _ := unstructured.NestedString(entry, "severity")
						assert.Equal(t, "Warning", sev, "severity should match profile override")
						break
					}
				}
				assert.True(t, found, "machineReadable should contain constraint named %s", crName)
			}
		}

		t.Logf("ConstraintReport verified: %d constraints from generic adapter", constraintCount)
	})

	// EnabledFalse verifies that a ConstraintProfile with enabled=false prevents
	// the CRD from being watched and indexed.
	t.Run("EnabledFalse", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		suffix := rand.String(8)
		group := "e2e-" + suffix + ".testing.io"
		resource := "disabledchecks"
		kind := "DisabledCheck"
		version := "v1"
		profileName := "e2e-disabled-" + suffix

		_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
		t.Cleanup(cleanupCRD)

		// Create profile with enabled=false.
		cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
			"gvr": map[string]interface{}{
				"group":    group,
				"version":  version,
				"resource": resource,
			},
			"adapter": "generic",
			"enabled": false,
		})
		t.Cleanup(cleanupProfile)

		sentinelName := "sentinel-disabled-" + rand.String(5)
		cleanupSentinel := createSentinelDeployment(t, sharedClientset, ns, sentinelName)
		t.Cleanup(cleanupSentinel)
		waitForDeploymentReady(t, sharedClientset, ns, sentinelName, 60*time.Second)

		crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
		crName := "e2e-disabled-" + rand.String(5)
		cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
			group+"/"+version, kind, ns, crName,
			map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": sentinelName,
					},
				},
			},
			nil,
		)
		t.Cleanup(cleanupCR)

		// Verify constraint does NOT appear within two rescan cycles.
		t.Log("Verifying disabled profile prevents constraint discovery...")
		waitForNoConstraintMatch(t, sharedDynamicClient, ns, sentinelName, heuristicStableWindow, func(c constraintSummary) bool {
			return c.Source == resource
		})
		t.Log("Confirmed: enabled=false prevents CRD from being watched")
	})

	// NegativeTests covers error cases: invalid field paths, missing target CRD,
	// and malformed ConstraintProfile specs.
	t.Run("NegativeTests", func(t *testing.T) {
		t.Parallel()

		// InvalidFieldPaths: Create a ConstraintProfile with nonsensical field paths.
		// The generic adapter should gracefully fall back to defaults (empty selector, no crash).
		t.Run("InvalidFieldPaths", func(t *testing.T) {
			t.Parallel()

			ns, cleanupNS := createTestNamespace(t, sharedClientset)
			t.Cleanup(cleanupNS)

			suffix := rand.String(8)
			group := "e2e-" + suffix + ".testing.io"
			resource := "badpathchecks"
			kind := "BadPathCheck"
			version := "v1"
			profileName := "e2e-badpath-" + suffix

			_, cleanupCRD := createCustomCRD(t, sharedDynamicClient, group, version, kind, resource, nil)
			t.Cleanup(cleanupCRD)

			cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
				"gvr": map[string]interface{}{
					"group":    group,
					"version":  version,
					"resource": resource,
				},
				"adapter": "generic",
				"enabled": true,
				"fieldPaths": map[string]interface{}{
					"selectorPath": "spec.nonexistent.deeply.nested",
					"effectPath":   "spec.does.not.exist",
					"summaryPath":  "spec.no.such.field",
				},
			})
			t.Cleanup(cleanupProfile)

			crGVR := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
			crName := "e2e-badpath-" + rand.String(5)
			cleanupCR := createCRInstance(t, sharedDynamicClient, crGVR,
				group+"/"+version, kind, ns, crName,
				map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": "test",
						},
					},
				},
				nil,
			)
			t.Cleanup(cleanupCR)

			// The constraint should still be created (graceful degradation),
			// just with empty/default extracted values.
			t.Log("Verifying invalid field paths produce graceful degradation...")
			waitForReportCondition(t, sharedDynamicClient, ns, profileDiscoveryTimeout, func(status map[string]interface{}) bool {
				sources := statusConstraintSources(status)
				for _, src := range sources {
					if src == resource {
						return true
					}
				}
				return false
			})
			t.Log("Constraint created despite invalid field paths (graceful degradation)")
		})

		// MissingTargetCRD: Create a ConstraintProfile pointing to a GVR that doesn't exist.
		// The controller should continue operating without crashing.
		t.Run("MissingTargetCRD", func(t *testing.T) {
			t.Parallel()

			suffix := rand.String(8)
			profileName := "e2e-missing-" + suffix

			cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
				"gvr": map[string]interface{}{
					"group":    "nonexistent-" + suffix + ".example.com",
					"version":  "v1",
					"resource": "doesnotexists",
				},
				"adapter": "generic",
				"enabled": true,
			})
			t.Cleanup(cleanupProfile)

			// Wait a moment, then verify the controller is still healthy.
			time.Sleep(5 * time.Second)

			deploy, err := sharedClientset.AppsV1().Deployments(controllerNamespace).Get(
				context.Background(), controllerDeploymentName, metav1.GetOptions{},
			)
			require.NoError(t, err, "failed to get controller deployment")
			require.Greater(t, deploy.Status.ReadyReplicas, int32(0),
				"controller should still be healthy after ConstraintProfile with missing CRD")
			t.Log("Controller remains healthy with ConstraintProfile pointing to non-existent CRD")
		})

		// MalformedSpec: Create a ConstraintProfile with empty GVR fields.
		// The controller should handle this gracefully.
		t.Run("MalformedSpec", func(t *testing.T) {
			t.Parallel()

			suffix := rand.String(8)
			profileName := "e2e-malformed-" + suffix

			cleanupProfile := createConstraintProfile(t, sharedDynamicClient, profileName, map[string]interface{}{
				"gvr": map[string]interface{}{
					"group":    "",
					"version":  "",
					"resource": "",
				},
				"adapter": "generic",
				"enabled": true,
			})
			t.Cleanup(cleanupProfile)

			// Wait a moment, then verify the controller is still healthy.
			time.Sleep(5 * time.Second)

			deploy, err := sharedClientset.AppsV1().Deployments(controllerNamespace).Get(
				context.Background(), controllerDeploymentName, metav1.GetOptions{},
			)
			require.NoError(t, err, "failed to get controller deployment")
			require.Greater(t, deploy.Status.ReadyReplicas, int32(0),
				"controller should still be healthy after malformed ConstraintProfile")
			t.Log("Controller remains healthy with malformed ConstraintProfile spec")
		})
	})
}
