//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for Potoo's MCP server HTTP interface.
// These tests verify that AI agents can query constraint data, get capabilities,
// and receive privacy-scoped responses through the MCP server endpoints.
//
// Requires a running cluster with the controller deployed and mcp.enabled=true.
package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
)

func TestMCP(t *testing.T) {
	t.Parallel()

	// Start a single port-forward shared by all subtests in this group.
	// The port-forward targets svc/potoo:8090 in the controller namespace.
	pf := startMCPPortForward(t)

	t.Run("HealthEndpoint", func(t *testing.T) {
		t.Parallel()

		result := mcpGet(t, pf, "/resources/health")

		assert.Equal(t, "healthy", result["status"], "health status should be 'healthy'")

		// Verify MCP section is present and enabled.
		mcpSection, ok := result["mcp"].(map[string]interface{})
		require.True(t, ok, "health response should contain 'mcp' section")
		assert.Equal(t, true, mcpSection["enabled"], "MCP should be enabled")

		// Verify indexer section is present.
		indexerSection, ok := result["indexer"].(map[string]interface{})
		require.True(t, ok, "health response should contain 'indexer' section")
		assert.NotNil(t, indexerSection["total_constraints"], "indexer should report total_constraints")

		t.Logf("Health: status=%s, indexer.total_constraints=%v", result["status"], indexerSection["total_constraints"])
	})

	t.Run("CapabilitiesEndpoint", func(t *testing.T) {
		t.Parallel()

		result := mcpGet(t, pf, "/resources/capabilities")

		assert.NotEmpty(t, result["version"], "capabilities should include version")
		assert.Equal(t, true, result["mcpEnabled"], "MCP should be enabled in capabilities")

		adapters, ok := result["adapters"].([]interface{})
		require.True(t, ok, "capabilities should contain 'adapters' array")
		assert.NotEmpty(t, adapters, "adapters list should not be empty")

		totalConstraints, ok := result["totalConstraints"].(float64)
		require.True(t, ok, "capabilities should contain 'totalConstraints'")
		assert.GreaterOrEqual(t, totalConstraints, float64(0), "totalConstraints should be >= 0")

		t.Logf("Capabilities: version=%s, adapters=%d, totalConstraints=%v",
			result["version"], len(adapters), totalConstraints)
	})

	t.Run("ToolsList", func(t *testing.T) {
		t.Parallel()

		result := mcpGet(t, pf, "/mcp/tools")

		tools, ok := result["tools"].([]interface{})
		require.True(t, ok, "response should contain 'tools' array")

		expectedTools := map[string]bool{
			"potoo_query":           false,
			"potoo_explain":         false,
			"potoo_check":           false,
			"potoo_list_namespaces": false,
			"potoo_remediation":     false,
		}

		for _, raw := range tools {
			tool, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := tool["name"].(string)
			if _, exists := expectedTools[name]; exists {
				expectedTools[name] = true
				// Verify each tool has an input schema.
				assert.NotNil(t, tool["inputSchema"], "tool %s should have inputSchema", name)
			}
		}

		for name, found := range expectedTools {
			assert.True(t, found, "expected tool %s not found in /mcp/tools", name)
		}
		t.Logf("Found %d tools", len(tools))
	})

	t.Run("ResourcesList", func(t *testing.T) {
		t.Parallel()

		result := mcpGet(t, pf, "/mcp/resources")

		resources, ok := result["resources"].([]interface{})
		require.True(t, ok, "response should contain 'resources' array")
		assert.Len(t, resources, 4, "should have 4 resources (reports, constraints, health, capabilities)")

		t.Logf("Found %d resources", len(resources))
	})

	t.Run("QueryWithConstraints", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a deny-all ingress NetworkPolicy.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-deny-ingress",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, np)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "mcp-e2e-deny-ingress")
		})

		// Wait for the own-namespace NetworkPolicy constraint to appear. Use a
		// non-redacted name check to avoid matching cluster-scoped constraints
		// that appear in ByNamespace results.
		constraint := waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			name, _ := c["name"].(string)
			return c["constraint_type"] == "NetworkIngress" && name != "redacted"
		})

		assert.Equal(t, "NetworkIngress", constraint["constraint_type"])
		assert.Equal(t, "Warning", constraint["severity"], "NetworkPolicy ingress should have Warning severity")
		assert.Equal(t, "restrict", constraint["effect"], "NetworkPolicy should have restrict effect")
		assert.Equal(t, "NetworkPolicy", constraint["source_kind"], "source_kind should be NetworkPolicy")

		t.Logf("Query returned constraint: type=%s, severity=%s, name=%s",
			constraint["constraint_type"], constraint["severity"], constraint["name"])
	})

	t.Run("QueryWithTypeFilter", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create an egress NetworkPolicy.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-egress-filter",
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
			}, ns, "mcp-e2e-egress-filter")
		})

		// Wait for constraint to be indexed.
		waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkEgress"
		})

		// Query with type filter for NetworkEgress.
		result := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace":       ns,
			"constraint_type": "NetworkEgress",
		})

		constraints, ok := result["constraints"].([]interface{})
		require.True(t, ok, "response should contain 'constraints' array")
		assert.NotEmpty(t, constraints, "should have at least one NetworkEgress constraint")

		for _, raw := range constraints {
			c, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			assert.Equal(t, "NetworkEgress", c["constraint_type"],
				"all constraints should be NetworkEgress when filtered")
		}

		// Query with filter for a type that doesn't exist in this namespace.
		result2 := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace":       ns,
			"constraint_type": "MeshPolicy",
		})
		total2, _ := result2["total"].(float64)
		assert.Equal(t, float64(0), total2, "MeshPolicy filter should return 0 for namespace with only network policies")

		t.Logf("Type filter: NetworkEgress=%d, MeshPolicy=%d", len(constraints), int(total2))
	})

	t.Run("QueryWithLabelFilter", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy targeting pods with label app=target-app.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-label-filter",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": "target-app",
						},
					},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, np)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "mcp-e2e-label-filter")
		})

		// Wait for constraint to be indexed.
		waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkIngress"
		})

		// Query with matching workload labels — should return the constraint.
		result := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace": ns,
			"workload_labels": map[string]string{
				"app": "target-app",
			},
		})
		total, _ := result["total"].(float64)
		assert.GreaterOrEqual(t, total, float64(1), "query with matching labels should return at least 1 constraint")

		// Query with non-matching workload labels — should return fewer or zero
		// constraints (only cluster-scoped constraints that match all labels remain).
		result2 := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace": ns,
			"workload_labels": map[string]string{
				"app": "non-existent-app",
			},
		})
		total2, _ := result2["total"].(float64)
		assert.Less(t, total2, total,
			"non-matching labels should return fewer constraints than matching labels")
		t.Logf("Label filter: matching=%d, non-matching=%d", int(total), int(total2))
	})

	t.Run("QueryEmptyNamespace", func(t *testing.T) {
		t.Parallel()

		// Use a unique namespace with no constraints.
		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Small delay to let the controller see the namespace.
		time.Sleep(2 * time.Second)

		result := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace": ns,
		})

		constraints, ok := result["constraints"].([]interface{})
		require.True(t, ok, "response should contain 'constraints' array")
		// Note: cluster-scoped constraints may appear, so we verify no namespace-scoped ones.
		for _, raw := range constraints {
			c, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			// Any namespace-specific constraint in this empty namespace would be unexpected.
			cNS, _ := c["namespace"].(string)
			assert.NotEqual(t, ns, cNS,
				"no namespace-scoped constraints should exist in a fresh empty namespace")
		}

		total, _ := result["total"].(float64)
		t.Logf("Empty namespace query: total=%d (may include cluster-scoped)", int(total))
	})

	t.Run("ConstraintResource", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		npName := "mcp-e2e-constraint-res"
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      npName,
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, np)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, npName)
		})

		// Wait for the own-namespace constraint to be indexed. At Summary privacy
		// level, own-namespace constraints show their real name (not "redacted").
		// Match by type AND non-redacted name to avoid picking up cluster-scoped constraints.
		constraint := waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			name, _ := c["name"].(string)
			return c["constraint_type"] == "NetworkIngress" && name != "redacted"
		})
		constraintName, _ := constraint["name"].(string)
		require.NotEmpty(t, constraintName, "constraint should have a non-redacted name")

		// Fetch individual constraint resource.
		detail := mcpGet(t, pf, "/resources/constraints/"+ns+"/"+constraintName)

		assert.Equal(t, constraintName, detail["name"])
		assert.Equal(t, "NetworkIngress", detail["constraint_type"])
		assert.NotEmpty(t, detail["severity"])
		assert.NotEmpty(t, detail["source_kind"])

		t.Logf("Constraint resource: name=%s, type=%s", detail["name"], detail["constraint_type"])
	})

	t.Run("ReportResource", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a constraint so the report has data.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-report",
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
			}, ns, "mcp-e2e-report")
		})

		// Wait for the constraint to be indexed.
		waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkEgress"
		})

		// Fetch the report resource.
		report := mcpGet(t, pf, "/resources/reports/"+ns)

		assert.Equal(t, ns, report["namespace"])
		assert.Equal(t, "1", report["schemaVersion"])
		assert.NotNil(t, report["constraintCount"])
		assert.NotNil(t, report["generatedAt"])

		constraintCount, _ := report["constraintCount"].(float64)
		assert.GreaterOrEqual(t, constraintCount, float64(1), "report should contain at least 1 constraint")

		t.Logf("Report: namespace=%s, constraintCount=%d, schemaVersion=%s",
			report["namespace"], int(constraintCount), report["schemaVersion"])
	})

	t.Run("PrivacyScopingSummary", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a namespace-scoped NetworkPolicy (should show real name).
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-privacy-own",
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		applyUnstructured(t, sharedDynamicClient, np)
		t.Cleanup(func() {
			deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
				Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
			}, ns, "mcp-e2e-privacy-own")
		})

		// Wait for the namespace-scoped constraint to be indexed.
		waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkIngress"
		})

		// Query constraints for this namespace at default Summary level.
		// The default PrivacyResolver returns DetailLevelSummary.
		result := mcpPost(t, pf, "/tools/potoo_query", map[string]interface{}{
			"namespace": ns,
		})

		constraints, ok := result["constraints"].([]interface{})
		require.True(t, ok)

		var ownNSNameVisible bool
		var clusterScopedRedacted bool

		for _, raw := range constraints {
			c, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := c["name"].(string)
			cNS, _ := c["namespace"].(string)

			// Own-namespace constraints should show real names.
			if cNS == ns && name != "redacted" {
				ownNSNameVisible = true
			}

			// Cluster-scoped constraints (namespace="" in response due to Summary scoping)
			// or constraints from other namespaces should be redacted.
			// At Summary level, scopedConstraintName redacts when namespace != viewerNamespace,
			// which includes cluster-scoped (namespace="").
			if name == "redacted" {
				clusterScopedRedacted = true
			}
		}

		if ownNSNameVisible {
			t.Logf("Privacy: own-namespace constraint names are visible (correct)")
		}
		if clusterScopedRedacted {
			t.Logf("Privacy: cluster-scoped/cross-namespace constraint names are redacted (correct)")
		}

		// At minimum, own-namespace constraints should show real names.
		assert.True(t, ownNSNameVisible,
			"own-namespace constraints should show real names at Summary level")

		// The E2E cluster has cluster-scoped constraints (e.g., ValidatingWebhookConfigurations
		// from the potoo webhook, Gatekeeper, Kyverno). At Summary level, cluster-scoped
		// constraint names (Namespace="") must be redacted per PRIVACY_MODEL.md.
		// scopedConstraintName returns "redacted" when c.Namespace != viewerNamespace,
		// which includes cluster-scoped constraints (c.Namespace == "").
		if len(constraints) > 1 {
			assert.True(t, clusterScopedRedacted,
				"cluster-scoped constraint names should be redacted at Summary level (found %d constraints, none redacted)", len(constraints))
		}
	})

	t.Run("ListNamespaces", func(t *testing.T) {
		t.Parallel()

		// Create two namespaces with constraints.
		ns1, cleanupNS1 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS1)
		ns2, cleanupNS2 := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS2)

		for _, ns := range []string{ns1, ns2} {
			npName := "mcp-e2e-listns-" + rand.String(4)
			np := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "networking.k8s.io/v1",
					"kind":       "NetworkPolicy",
					"metadata": map[string]interface{}{
						"name":      npName,
						"namespace": ns,
					},
					"spec": map[string]interface{}{
						"podSelector": map[string]interface{}{},
						"policyTypes": []interface{}{"Ingress"},
					},
				},
			}
			applyUnstructured(t, sharedDynamicClient, np)
			localNS := ns
			localName := npName
			t.Cleanup(func() {
				deleteUnstructured(t, sharedDynamicClient, schema.GroupVersionResource{
					Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
				}, localNS, localName)
			})
		}

		// Wait for both namespaces to have indexed constraints.
		waitForMCPConstraint(t, pf, ns1, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkIngress"
		})
		waitForMCPConstraint(t, pf, ns2, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkIngress"
		})

		// ListNamespaces returns a JSON array, not a wrapped object.
		summaries := mcpPostArray(t, pf, "/tools/potoo_list_namespaces", map[string]interface{}{})

		// Verify both namespaces appear in the list.
		foundNS1, foundNS2 := false, false
		for _, raw := range summaries {
			summary, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			nsName, _ := summary["namespace"].(string)
			if nsName == ns1 {
				foundNS1 = true
				total, _ := summary["total"].(float64)
				assert.GreaterOrEqual(t, total, float64(1), "ns1 should have at least 1 constraint")
			}
			if nsName == ns2 {
				foundNS2 = true
				total, _ := summary["total"].(float64)
				assert.GreaterOrEqual(t, total, float64(1), "ns2 should have at least 1 constraint")
			}
		}

		assert.True(t, foundNS1, "ns1 (%s) should appear in list_namespaces", ns1)
		assert.True(t, foundNS2, "ns2 (%s) should appear in list_namespaces", ns2)
		t.Logf("ListNamespaces: total summaries=%d, ns1=%v, ns2=%v", len(summaries), foundNS1, foundNS2)
	})

	t.Run("ExplainNetworkError", func(t *testing.T) {
		t.Parallel()

		ns, cleanupNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupNS)

		// Create a NetworkPolicy.
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "mcp-e2e-explain",
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
			}, ns, "mcp-e2e-explain")
		})

		// Wait for constraint to be indexed.
		waitForMCPConstraint(t, pf, ns, mcpQueryTimeout, func(c map[string]interface{}) bool {
			return c["constraint_type"] == "NetworkEgress"
		})

		// Explain a network-related error.
		result := mcpPost(t, pf, "/tools/potoo_explain", map[string]interface{}{
			"error_message": "connection refused to downstream-service:8080",
			"namespace":     ns,
		})

		confidence, _ := result["confidence"].(string)
		assert.Equal(t, "high", confidence,
			"'connection refused' should match with high confidence to network constraints")

		matchingConstraints, ok := result["matching_constraints"].([]interface{})
		require.True(t, ok, "response should contain 'matching_constraints'")
		assert.NotEmpty(t, matchingConstraints, "should match at least one constraint")

		explanation, _ := result["explanation"].(string)
		assert.Contains(t, explanation, "network",
			"explanation for 'connection refused' should mention network")

		t.Logf("Explain: confidence=%s, matches=%d, explanation=%s",
			confidence, len(matchingConstraints), explanation)
	})
}
