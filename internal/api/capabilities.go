// Package api provides HTTP API endpoints for Potoo.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

// CapabilitiesResponse is the response for GET /api/v1/capabilities.
type CapabilitiesResponse struct {
	// Version is the API schema version. Currently "1".
	Version string `json:"version"`

	// Adapters lists enabled adapter names.
	Adapters []AdapterInfo `json:"adapters"`

	// ConstraintTypes maps constraint types to counts.
	ConstraintTypes map[string]int `json:"constraintTypes"`

	// TotalConstraints is the total number of indexed constraints.
	TotalConstraints int `json:"totalConstraints"`

	// NamespaceCount is the number of namespaces with constraints.
	NamespaceCount int `json:"namespaceCount"`

	// WatchedResources is the total count of watched resource types.
	WatchedResources int `json:"watchedResources"`

	// HubbleStatus describes Hubble integration status.
	HubbleStatus *HubbleStatus `json:"hubbleStatus,omitempty"`

	// MCPStatus describes MCP server status.
	MCPStatus *MCPStatus `json:"mcpStatus,omitempty"`

	// LastScanTime is when constraints were last scanned.
	LastScanTime string `json:"lastScanTime"`

	// UpSince is when the controller started.
	UpSince string `json:"upSince,omitempty"`
}

// AdapterInfo describes an adapter.
type AdapterInfo struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	WatchedResources []string `json:"watchedResources,omitempty"`
	ConstraintCount  int      `json:"constraintCount"`
	ErrorCount       int      `json:"errorCount,omitempty"`
	Reason           string   `json:"reason,omitempty"` // why disabled
}

// HubbleStatus describes Hubble integration.
type HubbleStatus struct {
	Enabled   bool   `json:"enabled"`
	Connected bool   `json:"connected"`
	Address   string `json:"address,omitempty"`
}

// MCPStatus describes MCP server status.
type MCPStatus struct {
	Enabled   bool   `json:"enabled"`
	Transport string `json:"transport"`
	Port      int    `json:"port"`
}

// CapabilitiesHandler handles GET /api/v1/capabilities.
type CapabilitiesHandler struct {
	logger       *zap.Logger
	indexer      *indexer.Indexer
	adapters     []AdapterInfo
	hubbleStatus *HubbleStatus
	mcpStatus    *MCPStatus
	startTime    time.Time
	lastScanTime time.Time
}

// CapabilitiesHandlerOptions configures the CapabilitiesHandler.
type CapabilitiesHandlerOptions struct {
	Adapters     []AdapterInfo
	HubbleStatus *HubbleStatus
	MCPStatus    *MCPStatus
}

// NewCapabilitiesHandler creates a new CapabilitiesHandler.
func NewCapabilitiesHandler(
	idx *indexer.Indexer,
	logger *zap.Logger,
	opts CapabilitiesHandlerOptions,
) *CapabilitiesHandler {
	return &CapabilitiesHandler{
		logger:       logger.Named("capabilities"),
		indexer:      idx,
		adapters:     opts.Adapters,
		hubbleStatus: opts.HubbleStatus,
		mcpStatus:    opts.MCPStatus,
		startTime:    time.Now(),
	}
}

// SetLastScanTime updates the last scan timestamp.
func (h *CapabilitiesHandler) SetLastScanTime(t time.Time) {
	h.lastScanTime = t
}

// ServeHTTP implements http.Handler.
func (h *CapabilitiesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := h.buildResponse()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode capabilities response", zap.Error(err))
	}
}

// buildResponse constructs the CapabilitiesResponse from current state.
func (h *CapabilitiesHandler) buildResponse() CapabilitiesResponse {
	allConstraints := h.indexer.All()

	// Count by type
	typeCount := make(map[string]int)
	for _, c := range allConstraints {
		typeCount[string(c.ConstraintType)]++
	}

	// Count namespaces
	nsSet := make(map[string]bool)
	for _, c := range allConstraints {
		for _, ns := range c.AffectedNamespaces {
			nsSet[ns] = true
		}
		if c.Namespace != "" {
			nsSet[c.Namespace] = true
		}
	}

	// Count constraints per adapter
	adapterCounts := make(map[string]int)
	for _, c := range allConstraints {
		adapterName := resourceToAdapterName(c.Source.Resource)
		adapterCounts[adapterName]++
	}

	// Update adapter info with counts
	adapters := make([]AdapterInfo, len(h.adapters))
	watchedTotal := 0
	for i, a := range h.adapters {
		adapters[i] = a
		adapters[i].ConstraintCount = adapterCounts[a.Name]
		watchedTotal += len(a.WatchedResources)
	}

	lastScan := h.lastScanTime
	if lastScan.IsZero() {
		lastScan = time.Now()
	}

	return CapabilitiesResponse{
		Version:          "1",
		Adapters:         adapters,
		ConstraintTypes:  typeCount,
		TotalConstraints: len(allConstraints),
		NamespaceCount:   len(nsSet),
		WatchedResources: watchedTotal,
		HubbleStatus:     h.hubbleStatus,
		MCPStatus:        h.mcpStatus,
		LastScanTime:     lastScan.UTC().Format(time.RFC3339),
		UpSince:          h.startTime.UTC().Format(time.RFC3339),
	}
}

// resourceToAdapterName maps a resource name to an adapter name.
func resourceToAdapterName(resource string) string {
	switch resource {
	case "networkpolicies":
		return "networkpolicy"
	case "resourcequotas":
		return "resourcequota"
	case "limitranges":
		return "limitrange"
	case "validatingwebhookconfigurations", "mutatingwebhookconfigurations":
		return "webhookconfig"
	case "ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies":
		return "cilium"
	case "constrainttemplates", "constraints":
		return "gatekeeper"
	case "clusterpolicies", "policies":
		return "kyverno"
	case "authorizationpolicies", "peerauthentications", "sidecars":
		return "istio"
	default:
		return "generic"
	}
}

// DefaultAdapters returns the default adapter configuration.
func DefaultAdapters() []AdapterInfo {
	return []AdapterInfo{
		{
			Name:             "networkpolicy",
			Enabled:          true,
			WatchedResources: []string{"networkpolicies"},
		},
		{
			Name:             "resourcequota",
			Enabled:          true,
			WatchedResources: []string{"resourcequotas"},
		},
		{
			Name:             "limitrange",
			Enabled:          true,
			WatchedResources: []string{"limitranges"},
		},
		{
			Name:             "webhookconfig",
			Enabled:          true,
			WatchedResources: []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"},
		},
		{
			Name:             "gatekeeper",
			Enabled:          true,
			WatchedResources: []string{"constrainttemplates"},
		},
		{
			Name:             "kyverno",
			Enabled:          true,
			WatchedResources: []string{"clusterpolicies", "policies"},
		},
		{
			Name:             "cilium",
			Enabled:          true,
			WatchedResources: []string{"ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"},
		},
		{
			Name:             "istio",
			Enabled:          true,
			WatchedResources: []string{"authorizationpolicies", "peerauthentications", "sidecars"},
		},
		{
			Name:             "generic",
			Enabled:          true,
			WatchedResources: []string{},
		},
	}
}

// HealthHandler handles GET /health and GET /api/v1/health.
type HealthHandler struct {
	logger  *zap.Logger
	indexer *indexer.Indexer
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(idx *indexer.Indexer, logger *zap.Logger) *HealthHandler {
	return &HealthHandler{
		logger:  logger.Named("health"),
		indexer: idx,
	}
}

// HealthResponse is the response for health endpoints.
type HealthResponse struct {
	Status    string `json:"status"` // healthy, degraded, unhealthy
	Indexer   string `json:"indexer"`
	Timestamp string `json:"timestamp"`
}

// ServeHTTP implements http.Handler.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := "healthy"
	indexerStatus := "ready"

	if h.indexer == nil {
		status = "unhealthy"
		indexerStatus = "not initialized"
	}

	response := HealthResponse{
		Status:    status,
		Indexer:   indexerStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode health response", zap.Error(err))
	}
}

// RegisterHandlers registers API handlers on the given mux.
func RegisterHandlers(mux *http.ServeMux, idx *indexer.Indexer, logger *zap.Logger, opts CapabilitiesHandlerOptions) {
	capHandler := NewCapabilitiesHandler(idx, logger, opts)
	healthHandler := NewHealthHandler(idx, logger)
	constraintsHandler := NewConstraintsHandler(idx, logger)

	mux.Handle("/api/v1/capabilities", capHandler)
	mux.Handle("/api/v1/constraints", constraintsHandler)
	mux.Handle("/api/v1/health", healthHandler)
	mux.Handle("/health", healthHandler)
}

// ExtraHandlers returns a map of path → http.Handler suitable for
// controller-runtime's metricsserver.Options.ExtraHandlers.
func ExtraHandlers(idx *indexer.Indexer, logger *zap.Logger, opts CapabilitiesHandlerOptions) map[string]http.Handler {
	capHandler := NewCapabilitiesHandler(idx, logger, opts)
	healthHandler := NewHealthHandler(idx, logger)
	constraintsHandler := NewConstraintsHandler(idx, logger)

	return map[string]http.Handler{
		"/api/v1/capabilities": capHandler,
		"/api/v1/constraints":  constraintsHandler,
		"/api/v1/health":       healthHandler,
		"/health":              healthHandler,
	}
}

// unused but helps with type checking
var _ = types.ConstraintType("")
