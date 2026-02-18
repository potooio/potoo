package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/potooio/potoo/internal/types"
)

func TestConstraintsHandler_ByNamespace(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints?namespace=team-alpha", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// team-alpha has netpol-1 (namespaced), quota-1 (namespaced), and
	// webhook-1 (cluster-scoped, AffectedNamespaces includes team-alpha)
	assert.Len(t, response.Constraints, 3)

	names := make(map[string]bool)
	for _, c := range response.Constraints {
		names[c.Name] = true
	}
	assert.True(t, names["test-netpol"])
	assert.True(t, names["test-quota"])
	assert.True(t, names["test-webhook"])
}

func TestConstraintsHandler_AllConstraints(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	assert.Len(t, response.Constraints, 3)
}

func TestConstraintsHandler_EmptyNamespace(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints?namespace=nonexistent", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Only cluster-scoped webhook-1 should match (Namespace="" matches all)
	assert.Len(t, response.Constraints, 1)
	assert.Equal(t, "test-webhook", response.Constraints[0].Name)
}

func TestConstraintsHandler_MethodNotAllowed(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/constraints", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestConstraintsHandler_StripsRawObject(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	for _, c := range response.Constraints {
		assert.Nil(t, c.RawObject, "RawObject should be stripped from API response")
	}
}

func TestConstraintsHandler_PreservesSeverity(t *testing.T) {
	idx := setupTestIndexer()
	handler := NewConstraintsHandler(idx, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints?namespace=team-alpha", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	severities := make(map[string]types.Severity)
	for _, c := range response.Constraints {
		severities[c.Name] = c.Severity
	}
	assert.Equal(t, types.SeverityWarning, severities["test-netpol"])
	assert.Equal(t, types.SeverityCritical, severities["test-quota"])
	assert.Equal(t, types.SeverityInfo, severities["test-webhook"])
}

func TestConstraintsHandler_RegisteredOnMux(t *testing.T) {
	idx := setupTestIndexer()
	mux := http.NewServeMux()

	RegisterHandlers(mux, idx, zap.NewNop(), CapabilitiesHandlerOptions{Adapters: DefaultAdapters()})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints?namespace=team-alpha", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ConstraintsResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Constraints)
}

func TestExtraHandlers(t *testing.T) {
	idx := setupTestIndexer()
	handlers := ExtraHandlers(idx, zap.NewNop(), CapabilitiesHandlerOptions{Adapters: DefaultAdapters()})

	// Verify all expected paths are registered
	assert.Contains(t, handlers, "/api/v1/capabilities")
	assert.Contains(t, handlers, "/api/v1/constraints")
	assert.Contains(t, handlers, "/api/v1/health")
	assert.Contains(t, handlers, "/health")

	// Verify constraints handler works via ExtraHandlers
	h := handlers["/api/v1/constraints"]
	req := httptest.NewRequest(http.MethodGet, "/api/v1/constraints?namespace=team-alpha", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
