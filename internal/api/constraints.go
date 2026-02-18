package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

// ConstraintsResponse is the wire format for GET /api/v1/constraints.
// The webhook's ConstraintClient.Query() decodes this exact shape.
type ConstraintsResponse struct {
	Constraints []types.Constraint `json:"constraints"`
}

// ConstraintsHandler handles GET /api/v1/constraints.
type ConstraintsHandler struct {
	logger  *zap.Logger
	indexer *indexer.Indexer
}

// NewConstraintsHandler creates a new ConstraintsHandler.
func NewConstraintsHandler(idx *indexer.Indexer, logger *zap.Logger) *ConstraintsHandler {
	return &ConstraintsHandler{
		logger:  logger.Named("constraints"),
		indexer: idx,
	}
}

// ServeHTTP implements http.Handler.
func (h *ConstraintsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.indexer == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ConstraintsResponse{Constraints: []types.Constraint{}})
		return
	}

	namespace := r.URL.Query().Get("namespace")

	var constraints []types.Constraint
	if namespace != "" {
		constraints = h.indexer.ByNamespace(namespace)
	} else {
		constraints = h.indexer.All()
	}

	// Strip RawObject to avoid sending full unstructured objects over the wire.
	stripped := make([]types.Constraint, len(constraints))
	for i, c := range constraints {
		c.RawObject = nil
		stripped[i] = c
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ConstraintsResponse{Constraints: stripped}); err != nil {
		h.logger.Error("Failed to encode constraints response", zap.Error(err))
	}
}
