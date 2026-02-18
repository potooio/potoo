package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/requirements"
	"github.com/potooio/potoo/internal/types"
)

// mockEvalContext returns empty results for all queries, causing rules to detect missing resources.
type mockEvalContext struct{}

func (m *mockEvalContext) GetNamespace(_ context.Context, name string) (*unstructured.Unstructured, error) {
	ns := &unstructured.Unstructured{}
	ns.SetName(name)
	return ns, nil
}

func (m *mockEvalContext) ListByGVR(_ context.Context, _ schema.GroupVersionResource, _ string) ([]*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockEvalContext) FindMatchingResources(_ context.Context, _ schema.GroupVersionResource, _ string, _ map[string]string) ([]*unstructured.Unstructured, error) {
	return nil, nil
}

func setupTestServer() (*Server, *indexer.Indexer) {
	idx := indexer.New(nil)

	// Add some test constraints
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("netpol-1"),
		Name:               "restrict-egress",
		Namespace:          "team-alpha",
		AffectedNamespaces: []string{"team-alpha"},
		ConstraintType:     types.ConstraintTypeNetworkEgress,
		Severity:           types.SeverityWarning,
		Effect:             "restrict",
		Summary:            "Restricts egress to port 443",
		Tags:               []string{"network", "egress"},
		Source:             schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	})

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("quota-1"),
		Name:               "compute-quota",
		Namespace:          "team-alpha",
		AffectedNamespaces: []string{"team-alpha"},
		ConstraintType:     types.ConstraintTypeResourceLimit,
		Severity:           types.SeverityCritical,
		Effect:             "limit",
		Summary:            "CPU at 95%",
		Tags:               []string{"quota", "cpu"},
		Source:             schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
		Details: map[string]interface{}{
			"resources": map[string]interface{}{
				"cpu": map[string]interface{}{
					"hard":    "4",
					"used":    "3.8",
					"percent": 95,
				},
			},
		},
	})

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("webhook-1"),
		Name:               "pod-security",
		Namespace:          "",
		AffectedNamespaces: []string{"team-alpha", "team-beta"},
		ConstraintType:     types.ConstraintTypeAdmission,
		Severity:           types.SeverityInfo,
		Effect:             "intercept",
		Summary:            "Validates pod security",
		Tags:               []string{"admission", "security"},
		Source:             schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
	})

	opts := ServerOptions{
		Port:           8090,
		Transport:      "sse",
		Logger:         zap.NewNop(),
		DefaultContact: "platform@example.com",
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
	}

	server := NewServer(idx, opts)
	return server, idx
}

func TestHandlers_Query(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace:          "team-alpha",
		IncludeRemediation: true,
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result QueryResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "team-alpha", result.Namespace)
	assert.Equal(t, 3, result.Total)
	assert.Len(t, result.Constraints, 3)

	// Should be sorted by severity (critical first)
	assert.Equal(t, "Critical", result.Constraints[0].Severity)
	assert.Equal(t, "Warning", result.Constraints[1].Severity)
	assert.Equal(t, "Info", result.Constraints[2].Severity)

	// Should have remediation
	assert.NotNil(t, result.Constraints[0].Remediation)
}

func TestHandlers_Query_WithFilters(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace:      "team-alpha",
		ConstraintType: "NetworkEgress",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result QueryResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "NetworkEgress", result.Constraints[0].ConstraintType)
}

func TestHandlers_Explain(t *testing.T) {
	server, _ := setupTestServer()

	params := ExplainParams{
		ErrorMessage: "connection timed out",
		Namespace:    "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result ExplainResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "high", result.Confidence)
	assert.Contains(t, result.Explanation, "network")
	assert.Len(t, result.MatchingConstraints, 1)
	assert.Equal(t, "NetworkEgress", result.MatchingConstraints[0].ConstraintType)
}

func TestHandlers_Explain_Quota(t *testing.T) {
	server, _ := setupTestServer()

	params := ExplainParams{
		ErrorMessage: "exceeded quota for resource cpu",
		Namespace:    "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result ExplainResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "high", result.Confidence)
	assert.Contains(t, result.Explanation, "quota")
	assert.Len(t, result.MatchingConstraints, 1)
	assert.Equal(t, "ResourceLimit", result.MatchingConstraints[0].ConstraintType)
}

func TestHandlers_Check(t *testing.T) {
	server, _ := setupTestServer()

	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: team-alpha
  labels:
    app: test
spec:
  replicas: 1
`

	params := CheckParams{
		Manifest: manifest,
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	// No critical admission constraints, so should not block
	assert.False(t, result.WouldBlock)
}

func TestHandlers_ListNamespaces(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_list_namespaces", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleListNamespaces(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var summaries []NamespaceSummary
	err := json.NewDecoder(w.Body).Decode(&summaries)
	require.NoError(t, err)

	// Should have team-alpha and team-beta
	assert.GreaterOrEqual(t, len(summaries), 1)

	// Find team-alpha
	var teamAlpha *NamespaceSummary
	for i := range summaries {
		if summaries[i].Namespace == "team-alpha" {
			teamAlpha = &summaries[i]
			break
		}
	}

	require.NotNil(t, teamAlpha)
	assert.Equal(t, 3, teamAlpha.Total)
	assert.Equal(t, 1, teamAlpha.CriticalCount)
	assert.Equal(t, 1, teamAlpha.WarningCount)
	assert.Equal(t, 1, teamAlpha.InfoCount)
}

func TestHandlers_Remediation(t *testing.T) {
	server, _ := setupTestServer()

	params := RemediationParams{
		ConstraintName: "restrict-egress",
		Namespace:      "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_remediation", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleRemediation(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result RemediationResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.NotEmpty(t, result.Summary)
	assert.NotEmpty(t, result.Steps)
}

func TestHandlers_Remediation_NotFound(t *testing.T) {
	server, _ := setupTestServer()

	params := RemediationParams{
		ConstraintName: "nonexistent",
		Namespace:      "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_remediation", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleRemediation(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandlers_ReportResource(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/resources/reports/team-alpha", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleReportResource(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var report map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&report)
	require.NoError(t, err)

	assert.Equal(t, "team-alpha", report["namespace"])
	assert.Equal(t, float64(3), report["constraintCount"])
	assert.Equal(t, "1", report["schemaVersion"])
}

func TestHandlers_ConstraintResource(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/resources/constraints/team-alpha/restrict-egress", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleConstraintResource(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result ConstraintResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "restrict-egress", result.Name)
	assert.Equal(t, "NetworkEgress", result.ConstraintType)
	assert.NotNil(t, result.Remediation)
}

func TestHandlers_HealthResource(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/resources/health", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleHealthResource(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var health HealthResponse
	err := json.NewDecoder(w.Body).Decode(&health)
	require.NoError(t, err)

	assert.Equal(t, "healthy", health.Status)
	assert.True(t, health.MCP.Enabled)
	assert.Equal(t, 3, health.Indexer.TotalConstraints)
}

func TestHandlers_CapabilitiesResource(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/resources/capabilities", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleCapabilitiesResource(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var caps map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&caps)
	require.NoError(t, err)

	assert.Equal(t, "1", caps["version"])
	assert.NotNil(t, caps["adapters"])
	assert.True(t, caps["mcpEnabled"].(bool))
}

func TestServer_ToolsList(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/mcp/tools", nil)
	w := httptest.NewRecorder()

	server.handleToolsList(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	tools := response["tools"].([]interface{})
	assert.Len(t, tools, 5)

	// Check tool names
	toolNames := make(map[string]bool)
	for _, t := range tools {
		tool := t.(map[string]interface{})
		toolNames[tool["name"].(string)] = true
	}

	assert.True(t, toolNames["potoo_query"])
	assert.True(t, toolNames["potoo_explain"])
	assert.True(t, toolNames["potoo_check"])
	assert.True(t, toolNames["potoo_list_namespaces"])
	assert.True(t, toolNames["potoo_remediation"])
}

func TestServer_ResourcesList(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/mcp/resources", nil)
	w := httptest.NewRecorder()

	server.handleResourcesList(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	resources := response["resources"].([]interface{})
	assert.Len(t, resources, 4)
}

func TestToConstraintResult(t *testing.T) {
	c := types.Constraint{
		UID:            k8stypes.UID("test-uid"),
		Name:           "test-constraint",
		Namespace:      "test-ns",
		ConstraintType: types.ConstraintTypeNetworkEgress,
		Severity:       types.SeverityWarning,
		Effect:         "restrict",
		Tags:           []string{"network"},
		Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	result := ToConstraintResult(c, types.DetailLevelDetailed, "test-ns")

	assert.Equal(t, "test-constraint", result.Name)
	assert.Equal(t, "test-ns", result.Namespace)
	assert.Equal(t, "NetworkEgress", result.ConstraintType)
	assert.Equal(t, "Warning", result.Severity)
	assert.Equal(t, "restrict", result.Effect)
	assert.Equal(t, "NetworkPolicy", result.SourceKind)
	assert.Equal(t, "networking.k8s.io/v1", result.SourceAPIVersion)
	assert.Equal(t, "detailed", result.DetailLevel)
}

// --- New tests to boost coverage ---

func TestHandlers_Query_EmptyNamespace(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace: "", // empty namespace should return 400
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp map[string]string
	err := json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Contains(t, errResp["error"], "namespace is required")
}

func TestHandlers_Query_WithSeverityFilter(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace: "team-alpha",
		Severity:  "Critical",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result QueryResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "Critical", result.Constraints[0].Severity)
}

func TestHandlers_Query_WithLabels(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace:      "team-alpha",
		WorkloadLabels: map[string]string{"app": "test"},
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result QueryResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)
	// ByLabels may return a different subset; just check it succeeds
	assert.Equal(t, "team-alpha", result.Namespace)
}

func TestHandlers_Query_WithoutRemediation(t *testing.T) {
	server, _ := setupTestServer()

	params := QueryParams{
		Namespace:          "team-alpha",
		IncludeRemediation: false,
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result QueryResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, 3, result.Total)
	// Without remediation, Remediation should be nil for results
	for _, c := range result.Constraints {
		assert.Nil(t, c.Remediation)
	}
}

func TestHandlers_Query_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_query", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	server.handlers.HandleQuery(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Explain_NoMatchingConstraints(t *testing.T) {
	server, _ := setupTestServer()

	params := ExplainParams{
		ErrorMessage: "an unrelated log entry about health probes failing",
		Namespace:    "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result ExplainResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	// Should fall back to low confidence with all constraints
	assert.Equal(t, "low", result.Confidence)
	assert.Contains(t, result.Explanation, "Could not determine")
	assert.Len(t, result.MatchingConstraints, 3) // returns all constraints
}

func TestHandlers_Explain_MissingFields(t *testing.T) {
	server, _ := setupTestServer()

	// Missing error_message
	params := ExplainParams{
		Namespace: "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Explain_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader([]byte("{bad")))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Explain_AdmissionError(t *testing.T) {
	server, _ := setupTestServer()

	params := ExplainParams{
		ErrorMessage: "admission webhook denied the request",
		Namespace:    "team-alpha",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleExplain(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result ExplainResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "high", result.Confidence)
	assert.Contains(t, result.Explanation, "admission")
	// Should match the admission constraint
	found := false
	for _, mc := range result.MatchingConstraints {
		if mc.ConstraintType == "Admission" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should find an Admission constraint")
}

func TestHandlers_Check_WithBlockingConstraint(t *testing.T) {
	server, idx := setupTestServer()

	// Add a critical admission constraint that would block
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("admission-critical"),
		Name:               "block-pods",
		Namespace:          "",
		AffectedNamespaces: []string{"team-alpha"},
		ConstraintType:     types.ConstraintTypeAdmission,
		Severity:           types.SeverityCritical,
		Effect:             "deny",
		Summary:            "Blocks all pod creation",
		Source:             schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
	})

	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: team-alpha
  labels:
    app: test
spec:
  replicas: 1
`
	params := CheckParams{
		Manifest: manifest,
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.True(t, result.WouldBlock)
	assert.NotEmpty(t, result.BlockingConstraints)
}

func TestHandlers_Check_NoBlockingAllInfo(t *testing.T) {
	// Server with only info severity constraints
	idx := indexer.New(nil)
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("info-1"),
		Name:               "info-webhook",
		AffectedNamespaces: []string{"default"},
		ConstraintType:     types.ConstraintTypeAdmission,
		Severity:           types.SeverityInfo,
		Source:             schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
	})

	opts := ServerOptions{
		Port:      8090,
		Transport: "sse",
		Logger:    zap.NewNop(),
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
	}
	server := NewServer(idx, opts)

	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
  labels:
    app: my-app
`
	params := CheckParams{Manifest: manifest}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	assert.False(t, result.WouldBlock)
	assert.Empty(t, result.BlockingConstraints)
}

func TestHandlers_Check_WarningsGenerated(t *testing.T) {
	server, _ := setupTestServer()

	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: team-alpha
  labels:
    app: test
`
	params := CheckParams{Manifest: manifest}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	// The team-alpha constraints include a Warning severity one
	assert.NotEmpty(t, result.Warnings)
}

func TestHandlers_Check_InvalidManifest(t *testing.T) {
	server, _ := setupTestServer()

	// Use YAML that parses to non-map type -- yaml.Unmarshal into map will fail
	params := CheckParams{Manifest: "- item1\n- item2\n"}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	// A YAML list will fail to unmarshal into map[string]interface{}, returning 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Check_EmptyManifest(t *testing.T) {
	server, _ := setupTestServer()

	params := CheckParams{Manifest: ""}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Check_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader([]byte("{bad")))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Check_ManifestWithoutNamespace(t *testing.T) {
	server, _ := setupTestServer()

	// Manifest with no namespace defaults to "default"
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  labels:
    app: test
`
	params := CheckParams{Manifest: manifest}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)
	// Should not error, just use "default" namespace
	assert.False(t, result.WouldBlock)
}

func TestHandlers_ReportResource_EmptyNamespace(t *testing.T) {
	server, _ := setupTestServer()

	// Request with empty namespace path
	req := httptest.NewRequest(http.MethodGet, "/resources/reports/", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleReportResource(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_ReportResource_OtherNamespace(t *testing.T) {
	// Use a fresh indexer with only namespaced constraints (no cluster-scoped)
	idx := indexer.New(nil)
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("ns-only"),
		Name:               "ns-policy",
		Namespace:          "specific-ns",
		AffectedNamespaces: []string{"specific-ns"},
		ConstraintType:     types.ConstraintTypeNetworkEgress,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "networkpolicies"},
	})

	opts := ServerOptions{
		Logger: zap.NewNop(),
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
	}
	server := NewServer(idx, opts)

	// Query a namespace with no constraints
	req := httptest.NewRequest(http.MethodGet, "/resources/reports/empty-ns", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleReportResource(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var report map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&report)
	require.NoError(t, err)

	assert.Equal(t, "empty-ns", report["namespace"])
	assert.Equal(t, float64(0), report["constraintCount"])
	assert.Equal(t, "1", report["schemaVersion"])
}

func TestHandlers_ConstraintResource_NotFound(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/resources/constraints/team-alpha/nonexistent-constraint", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleConstraintResource(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandlers_ConstraintResource_MissingParts(t *testing.T) {
	server, _ := setupTestServer()

	// Only namespace, no name
	req := httptest.NewRequest(http.MethodGet, "/resources/constraints/team-alpha", nil)
	w := httptest.NewRecorder()

	server.handlers.HandleConstraintResource(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Remediation_MissingFields(t *testing.T) {
	server, _ := setupTestServer()

	params := RemediationParams{
		ConstraintName: "",
		Namespace:      "",
	}

	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_remediation", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleRemediation(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Remediation_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_remediation", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()

	server.handlers.HandleRemediation(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenericSummary_AllTypes(t *testing.T) {
	tests := []struct {
		ct       types.ConstraintType
		contains string
	}{
		{types.ConstraintTypeNetworkIngress, "Inbound network traffic"},
		{types.ConstraintTypeNetworkEgress, "Outbound network traffic"},
		{types.ConstraintTypeAdmission, "admission policy"},
		{types.ConstraintTypeResourceLimit, "quotas or limits"},
		{types.ConstraintTypeMeshPolicy, "mesh policies"},
		{types.ConstraintTypeMissing, "missing"},
		{types.ConstraintType("SomeUnknownType"), "policy constraint"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ct), func(t *testing.T) {
			result := genericSummary(tt.ct)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestSeverityOrder_AllCases(t *testing.T) {
	assert.Equal(t, 0, severityOrder("Critical"))
	assert.Equal(t, 1, severityOrder("Warning"))
	assert.Equal(t, 2, severityOrder("Info"))
	assert.Equal(t, 3, severityOrder("Unknown"))
	assert.Equal(t, 3, severityOrder(""))
	assert.Equal(t, 3, severityOrder("SomethingElse"))
}

func TestToConstraintResultWithRemediation(t *testing.T) {
	c := types.Constraint{
		UID:            k8stypes.UID("test-uid"),
		Name:           "test-constraint",
		Namespace:      "test-ns",
		ConstraintType: types.ConstraintTypeNetworkEgress,
		Severity:       types.SeverityWarning,
		Effect:         "restrict",
		Tags:           []string{"network"},
		Source:         schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	builder := func(c types.Constraint) RemediationInfo {
		return RemediationInfo{
			Summary: "Test remediation summary",
			Steps: []RemediationStepInfo{
				{
					Type:              "kubectl",
					Description:       "Run a command",
					Command:           "kubectl get pods",
					RequiresPrivilege: "developer",
				},
				{
					Type:        "manual",
					Description: "Contact admin",
					Contact:     "admin@example.com",
				},
				{
					Type:        "annotation",
					Description: "Add annotation",
					Patch:       "some-patch",
				},
				{
					Type:        "link",
					Description: "See docs",
					URL:         "https://example.com/docs",
				},
				{
					Type:        "yaml_patch",
					Description: "Apply template",
					Template:    "apiVersion: v1\nkind: ConfigMap",
				},
			},
		}
	}

	result := ToConstraintResultWithRemediation(c, types.DetailLevelDetailed, "test-ns", builder)

	assert.Equal(t, "test-constraint", result.Name)
	assert.Equal(t, "NetworkEgress", result.ConstraintType)
	assert.Equal(t, "Warning", result.Severity)
	require.NotNil(t, result.Remediation)
	assert.Equal(t, "Test remediation summary", result.Remediation.Summary)
	require.Len(t, result.Remediation.Steps, 5)

	// kubectl type should be automated
	assert.True(t, result.Remediation.Steps[0].Automated)
	assert.Equal(t, "kubectl get pods", result.Remediation.Steps[0].Command)

	// manual type should not be automated
	assert.False(t, result.Remediation.Steps[1].Automated)
	assert.Equal(t, "admin@example.com", result.Remediation.Steps[1].Contact)

	// annotation type should be automated
	assert.True(t, result.Remediation.Steps[2].Automated)
	assert.Equal(t, "some-patch", result.Remediation.Steps[2].Patch)

	// link type should not be automated
	assert.False(t, result.Remediation.Steps[3].Automated)
	assert.Equal(t, "https://example.com/docs", result.Remediation.Steps[3].URL)

	// yaml_patch should not be automated
	assert.False(t, result.Remediation.Steps[4].Automated)
	assert.Equal(t, "apiVersion: v1\nkind: ConfigMap", result.Remediation.Steps[4].Template)
}

func TestMatchErrorToConstraints_AllPatterns(t *testing.T) {
	// Create a server with all constraint types
	idx := indexer.New(nil)

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("net-1"),
		Name:               "net-ingress",
		AffectedNamespaces: []string{"test-ns"},
		ConstraintType:     types.ConstraintTypeNetworkIngress,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "networkpolicies"},
	})
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("net-2"),
		Name:               "net-egress",
		AffectedNamespaces: []string{"test-ns"},
		ConstraintType:     types.ConstraintTypeNetworkEgress,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "networkpolicies"},
	})
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("adm-1"),
		Name:               "admission-policy",
		AffectedNamespaces: []string{"test-ns"},
		ConstraintType:     types.ConstraintTypeAdmission,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
	})
	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("quota-1"),
		Name:               "resource-quota",
		AffectedNamespaces: []string{"test-ns"},
		ConstraintType:     types.ConstraintTypeResourceLimit,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "resourcequotas"},
	})

	opts := ServerOptions{
		Logger: zap.NewNop(),
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
	}
	server := NewServer(idx, opts)

	tests := []struct {
		name               string
		errorMessage       string
		expectedConfidence string
		expectedType       string
	}{
		{"network_dial", "dial tcp 10.0.0.1:443: i/o timeout", "high", "NetworkIngress"},
		{"network_no_route", "no route to host 10.0.0.5", "high", "NetworkIngress"},
		{"admission_denied", "admission webhook denied the request", "high", "Admission"},
		{"admission_forbidden", "Error: forbidden by policy", "high", "Admission"},
		{"admission_not_allowed", "operation not allowed on pods", "high", "Admission"},
		{"quota_exceeded", "exceeded quota for resource cpu", "high", "ResourceLimit"},
		{"quota_insufficient", "insufficient memory in namespace", "high", "ResourceLimit"},
		{"no_match", "completely unrelated error about something else", "low", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := ExplainParams{
				ErrorMessage: tt.errorMessage,
				Namespace:    "test-ns",
			}

			body, _ := json.Marshal(params)
			req := httptest.NewRequest(http.MethodPost, "/tools/potoo_explain", bytes.NewReader(body))
			w := httptest.NewRecorder()

			server.handlers.HandleExplain(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var result ExplainResult
			err := json.NewDecoder(w.Body).Decode(&result)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedConfidence, result.Confidence)

			if tt.expectedType != "" {
				found := false
				for _, mc := range result.MatchingConstraints {
					if mc.ConstraintType == tt.expectedType {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected to find constraint type %s", tt.expectedType)
			}
		})
	}
}

func TestNewServer_Defaults(t *testing.T) {
	idx := indexer.New(nil)

	// Test with zero values to verify defaults
	server := NewServer(idx, ServerOptions{})

	assert.NotNil(t, server)
	assert.Equal(t, 8090, server.opts.Port)
	assert.Equal(t, "sse", server.opts.Transport)
	assert.NotNil(t, server.opts.Logger)
	assert.NotNil(t, server.opts.PrivacyResolver)
}

func TestDefaultServerOptions(t *testing.T) {
	opts := DefaultServerOptions()

	assert.Equal(t, 8090, opts.Port)
	assert.Equal(t, "sse", opts.Transport)
	assert.Equal(t, "your platform team", opts.DefaultContact)
}

func TestServer_HandleTool_Middleware(t *testing.T) {
	server, _ := setupTestServer()

	// handleTool wraps a handler with method check and content-type
	handler := server.handleTool(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// POST should work
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	// GET should be rejected
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_HandleResource_Middleware(t *testing.T) {
	server, _ := setupTestServer()

	handler := server.handleResource(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// GET should work
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	// POST should be rejected
	req = httptest.NewRequest(http.MethodPost, "/test", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_BroadcastEvent_WithClients(t *testing.T) {
	server, _ := setupTestServer()

	// Manually add an SSE client
	clientChan := make(chan []byte, 100)
	server.mu.Lock()
	server.sseClients["test-client"] = clientChan
	server.mu.Unlock()

	data := map[string]interface{}{
		"test": "broadcast-data",
	}

	server.BroadcastEvent("test_event", data)

	// Should receive the broadcast
	select {
	case msg := <-clientChan:
		assert.Contains(t, string(msg), "test_event")
		assert.Contains(t, string(msg), "broadcast-data")
	default:
		t.Error("Expected to receive broadcast message")
	}

	// Cleanup
	server.mu.Lock()
	delete(server.sseClients, "test-client")
	close(clientChan)
	server.mu.Unlock()
}

func TestServer_ToolsList_WrongMethod(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools", nil)
	w := httptest.NewRecorder()

	server.handleToolsList(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_ResourcesList_WrongMethod(t *testing.T) {
	server, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodPost, "/mcp/resources", nil)
	w := httptest.NewRecorder()

	server.handleResourcesList(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_OnIndexChange(t *testing.T) {
	server, _ := setupTestServer()

	event := indexer.IndexEvent{
		Type: "upsert",
		Constraint: types.Constraint{
			UID:            k8stypes.UID("change-uid"),
			Name:           "changed-constraint",
			Namespace:      "team-alpha",
			ConstraintType: types.ConstraintTypeNetworkEgress,
			Severity:       types.SeverityWarning,
		},
	}

	// Should not panic
	server.OnIndexChange(event)
}

func TestServer_BroadcastEvent(t *testing.T) {
	server, _ := setupTestServer()

	data := map[string]interface{}{
		"test": "data",
	}

	// Should not panic even with no SSE clients
	server.BroadcastEvent("test_event", data)
}

func TestHandlers_Check_WithMissingPrerequisites(t *testing.T) {
	idx := indexer.New(nil)

	eval := requirements.NewEvaluator(idx, &mockEvalContext{}, zap.NewNop())
	eval.SetDebounceDuration(0) // Immediate results for pre-check
	eval.RegisterRule(requirements.NewPrometheusMonitorRule())

	opts := ServerOptions{
		Port:      8090,
		Transport: "sse",
		Logger:    zap.NewNop(),
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
		Evaluator: eval,
	}
	server := NewServer(idx, opts)

	// Deployment with a metrics port — should trigger missing ServiceMonitor
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: team-alpha
  labels:
    app: my-app
spec:
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: app
        ports:
        - name: metrics
          containerPort: 9090
`
	params := CheckParams{Manifest: manifest}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	// Should have missing prerequisites
	require.NotEmpty(t, result.MissingPrerequisites)
	assert.Equal(t, "ServiceMonitor", result.MissingPrerequisites[0].ExpectedKind)
	assert.Equal(t, "monitoring.coreos.com/v1", result.MissingPrerequisites[0].ExpectedAPIVersion)
	assert.NotEmpty(t, result.MissingPrerequisites[0].ForWorkload)
	assert.NotEmpty(t, result.MissingPrerequisites[0].Reason)
	assert.Equal(t, "Warning", result.MissingPrerequisites[0].Severity)
}

func TestHandlers_Check_NilEvaluator(t *testing.T) {
	// Server without evaluator — backward compatibility
	idx := indexer.New(nil)
	opts := ServerOptions{
		Logger: zap.NewNop(),
		PrivacyResolver: func(r *http.Request) types.DetailLevel {
			return types.DetailLevelDetailed
		},
	}
	server := NewServer(idx, opts)

	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  replicas: 1
`
	params := CheckParams{Manifest: manifest}
	body, _ := json.Marshal(params)
	req := httptest.NewRequest(http.MethodPost, "/tools/potoo_check", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handlers.HandleCheck(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result CheckResult
	err := json.NewDecoder(w.Body).Decode(&result)
	require.NoError(t, err)

	// Should have empty missing prerequisites (not nil)
	assert.Empty(t, result.MissingPrerequisites)
}

func TestToConstraintResult_PrivacyScoping(t *testing.T) {
	c := types.Constraint{
		UID:            k8stypes.UID("cross-ns-uid"),
		Name:           "secret-policy",
		Namespace:      "kube-system",
		ConstraintType: types.ConstraintTypeNetworkEgress,
		Severity:       types.SeverityCritical,
		Source:         schema.GroupVersionResource{Resource: "networkpolicies"},
	}

	// Summary level - cross namespace should be redacted
	result := ToConstraintResult(c, types.DetailLevelSummary, "team-alpha")
	assert.Equal(t, "redacted", result.Name)
	assert.Empty(t, result.Namespace)

	// Detailed level - should show name but not cross-namespace info
	result = ToConstraintResult(c, types.DetailLevelDetailed, "team-alpha")
	assert.Equal(t, "secret-policy", result.Name)
	assert.Empty(t, result.Namespace) // Still hidden for cross-namespace

	// Full level - should show everything
	result = ToConstraintResult(c, types.DetailLevelFull, "team-alpha")
	assert.Equal(t, "secret-policy", result.Name)
	assert.Equal(t, "kube-system", result.Namespace)
}
