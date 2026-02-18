package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

func setupTestIndexer() *indexer.Indexer {
	idx := indexer.New(nil)

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("netpol-1"),
		Name:               "test-netpol",
		Namespace:          "team-alpha",
		AffectedNamespaces: []string{"team-alpha"},
		ConstraintType:     types.ConstraintTypeNetworkEgress,
		Severity:           types.SeverityWarning,
		Source:             schema.GroupVersionResource{Resource: "networkpolicies"},
	})

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("quota-1"),
		Name:               "test-quota",
		Namespace:          "team-alpha",
		AffectedNamespaces: []string{"team-alpha"},
		ConstraintType:     types.ConstraintTypeResourceLimit,
		Severity:           types.SeverityCritical,
		Source:             schema.GroupVersionResource{Resource: "resourcequotas"},
	})

	idx.Upsert(types.Constraint{
		UID:                k8stypes.UID("webhook-1"),
		Name:               "test-webhook",
		Namespace:          "",
		AffectedNamespaces: []string{"team-alpha", "team-beta"},
		ConstraintType:     types.ConstraintTypeAdmission,
		Severity:           types.SeverityInfo,
		Source:             schema.GroupVersionResource{Resource: "validatingwebhookconfigurations"},
	})

	return idx
}

func TestCapabilitiesHandler(t *testing.T) {
	idx := setupTestIndexer()

	opts := CapabilitiesHandlerOptions{
		Adapters: DefaultAdapters(),
		MCPStatus: &MCPStatus{
			Enabled:   true,
			Transport: "sse",
			Port:      8090,
		},
	}

	handler := NewCapabilitiesHandler(idx, zap.NewNop(), opts)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response CapabilitiesResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "1", response.Version)
	assert.Equal(t, 3, response.TotalConstraints)
	assert.GreaterOrEqual(t, response.NamespaceCount, 2) // team-alpha and team-beta

	// Check constraint types
	assert.Equal(t, 1, response.ConstraintTypes["NetworkEgress"])
	assert.Equal(t, 1, response.ConstraintTypes["ResourceLimit"])
	assert.Equal(t, 1, response.ConstraintTypes["Admission"])

	// Check adapters
	assert.Len(t, response.Adapters, 9)

	// Check MCP status
	require.NotNil(t, response.MCPStatus)
	assert.True(t, response.MCPStatus.Enabled)
	assert.Equal(t, "sse", response.MCPStatus.Transport)
	assert.Equal(t, 8090, response.MCPStatus.Port)

	// Check timestamps
	assert.NotEmpty(t, response.LastScanTime)
	assert.NotEmpty(t, response.UpSince)
}

func TestCapabilitiesHandler_MethodNotAllowed(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewCapabilitiesHandler(idx, zap.NewNop(), CapabilitiesHandlerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestCapabilitiesHandler_AdapterCounts(t *testing.T) {
	idx := setupTestIndexer()

	opts := CapabilitiesHandlerOptions{
		Adapters: DefaultAdapters(),
	}

	handler := NewCapabilitiesHandler(idx, zap.NewNop(), opts)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var response CapabilitiesResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Find adapters and check counts
	adapterMap := make(map[string]AdapterInfo)
	for _, a := range response.Adapters {
		adapterMap[a.Name] = a
	}

	assert.Equal(t, 1, adapterMap["networkpolicy"].ConstraintCount)
	assert.Equal(t, 1, adapterMap["resourcequota"].ConstraintCount)
	assert.Equal(t, 1, adapterMap["webhookconfig"].ConstraintCount)
}

func TestCapabilitiesHandler_WithHubble(t *testing.T) {
	idx := setupTestIndexer()

	opts := CapabilitiesHandlerOptions{
		Adapters: DefaultAdapters(),
		HubbleStatus: &HubbleStatus{
			Enabled:   true,
			Connected: true,
			Address:   "hubble-relay.kube-system:4245",
		},
	}

	handler := NewCapabilitiesHandler(idx, zap.NewNop(), opts)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var response CapabilitiesResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	require.NotNil(t, response.HubbleStatus)
	assert.True(t, response.HubbleStatus.Enabled)
	assert.True(t, response.HubbleStatus.Connected)
	assert.Equal(t, "hubble-relay.kube-system:4245", response.HubbleStatus.Address)
}

func TestHealthHandler(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewHealthHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response HealthResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response.Status)
	assert.Equal(t, "ready", response.Indexer)
	assert.NotEmpty(t, response.Timestamp)
}

func TestHealthHandler_NilIndexer(t *testing.T) {
	handler := NewHealthHandler(nil, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response HealthResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "unhealthy", response.Status)
	assert.Equal(t, "not initialized", response.Indexer)
}

func TestHealthHandler_MethodNotAllowed(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewHealthHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestResourceToAdapterName(t *testing.T) {
	tests := []struct {
		resource string
		expected string
	}{
		{"networkpolicies", "networkpolicy"},
		{"resourcequotas", "resourcequota"},
		{"limitranges", "limitrange"},
		{"validatingwebhookconfigurations", "webhookconfig"},
		{"mutatingwebhookconfigurations", "webhookconfig"},
		{"ciliumnetworkpolicies", "cilium"},
		{"ciliumclusterwidenetworkpolicies", "cilium"},
		{"constrainttemplates", "gatekeeper"},
		{"constraints", "gatekeeper"},
		{"clusterpolicies", "kyverno"},
		{"policies", "kyverno"},
		{"authorizationpolicies", "istio"},
		{"peerauthentications", "istio"},
		{"sidecars", "istio"},
		{"unknown", "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			result := resourceToAdapterName(tt.resource)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultAdapters(t *testing.T) {
	adapters := DefaultAdapters()

	assert.Len(t, adapters, 9)

	names := make(map[string]bool)
	for _, a := range adapters {
		names[a.Name] = true
		assert.True(t, a.Enabled)
	}

	assert.True(t, names["networkpolicy"])
	assert.True(t, names["resourcequota"])
	assert.True(t, names["limitrange"])
	assert.True(t, names["webhookconfig"])
	assert.True(t, names["gatekeeper"])
	assert.True(t, names["kyverno"])
	assert.True(t, names["cilium"])
	assert.True(t, names["istio"])
	assert.True(t, names["generic"])
}

func TestRegisterHandlers(t *testing.T) {
	idx := setupTestIndexer()
	mux := http.NewServeMux()

	opts := CapabilitiesHandlerOptions{
		Adapters: DefaultAdapters(),
	}

	RegisterHandlers(mux, idx, zap.NewNop(), opts)

	// Test /api/v1/capabilities
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test /api/v1/health
	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test /health
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
