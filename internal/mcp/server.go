package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/requirements"
	"github.com/potooio/potoo/internal/types"
)

// PrivacyResolverFunc determines the detail level for a request based on
// authentication context (e.g., bearer token, ServiceAccount).
type PrivacyResolverFunc func(r *http.Request) types.DetailLevel

// ServerOptions configures the MCP server.
type ServerOptions struct {
	// Port is the HTTP port to listen on. Default: 8090.
	Port int

	// Transport is "sse" or "stdio". Default: "sse".
	Transport string

	// PrivacyResolver determines detail level based on request context.
	// If nil, defaults to DetailLevelSummary.
	PrivacyResolver PrivacyResolverFunc

	// Logger for server operations.
	Logger *zap.Logger

	// DefaultContact for remediation steps.
	DefaultContact string

	// Evaluator for missing-resource detection in pre-check. May be nil.
	Evaluator *requirements.Evaluator
}

// DefaultServerOptions returns sensible defaults.
func DefaultServerOptions() ServerOptions {
	return ServerOptions{
		Port:           8090,
		Transport:      "sse",
		DefaultContact: "your platform team",
	}
}

// Server is the MCP server that exposes Potoo data to AI agents.
type Server struct {
	logger     *zap.Logger
	indexer    *indexer.Indexer
	opts       ServerOptions
	handlers   *Handlers
	httpServer *http.Server

	mu              sync.RWMutex
	sseClients      map[string]chan []byte // client ID -> event channel
	clientIDCounter int
}

// NewServer creates a new MCP server.
func NewServer(idx *indexer.Indexer, opts ServerOptions) *Server {
	if opts.Port == 0 {
		opts.Port = 8090
	}
	if opts.Transport == "" {
		opts.Transport = "sse"
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.PrivacyResolver == nil {
		opts.PrivacyResolver = func(r *http.Request) types.DetailLevel {
			return types.DetailLevelSummary
		}
	}

	s := &Server{
		logger:     opts.Logger.Named("mcp-server"),
		indexer:    idx,
		opts:       opts,
		sseClients: make(map[string]chan []byte),
	}

	s.handlers = NewHandlers(idx, opts.PrivacyResolver, opts.DefaultContact, opts.Logger, opts.Evaluator)

	return s
}

// Start begins the MCP server. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Tool endpoints
	mux.HandleFunc("/tools/potoo_query", s.handleTool(s.handlers.HandleQuery))
	mux.HandleFunc("/tools/potoo_explain", s.handleTool(s.handlers.HandleExplain))
	mux.HandleFunc("/tools/potoo_check", s.handleTool(s.handlers.HandleCheck))
	mux.HandleFunc("/tools/potoo_list_namespaces", s.handleTool(s.handlers.HandleListNamespaces))
	mux.HandleFunc("/tools/potoo_remediation", s.handleTool(s.handlers.HandleRemediation))

	// Resource endpoints
	mux.HandleFunc("/resources/reports/", s.handleResource(s.handlers.HandleReportResource))
	mux.HandleFunc("/resources/constraints/", s.handleResource(s.handlers.HandleConstraintResource))
	mux.HandleFunc("/resources/health", s.handleResource(s.handlers.HandleHealthResource))
	mux.HandleFunc("/resources/capabilities", s.handleResource(s.handlers.HandleCapabilitiesResource))

	// SSE endpoint for streaming updates
	mux.HandleFunc("/sse", s.handleSSE)

	// MCP protocol endpoints
	mux.HandleFunc("/mcp/tools", s.handleToolsList)
	mux.HandleFunc("/mcp/resources", s.handleResourcesList)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.opts.Port),
		Handler: mux,
	}

	s.logger.Info("Starting MCP server",
		zap.Int("port", s.opts.Port),
		zap.String("transport", s.opts.Transport))

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutting down MCP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// handleTool wraps a tool handler with common middleware.
func (s *Server) handleTool(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}
}

// handleResource wraps a resource handler with common middleware.
func (s *Server) handleResource(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}
}

// handleSSE handles SSE connections for streaming updates.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create client channel
	s.mu.Lock()
	s.clientIDCounter++
	clientID := fmt.Sprintf("client-%d", s.clientIDCounter)
	clientChan := make(chan []byte, 100)
	s.sseClients[clientID] = clientChan
	s.mu.Unlock()

	s.logger.Debug("SSE client connected", zap.String("clientID", clientID))

	// Cleanup on disconnect
	defer func() {
		s.mu.Lock()
		delete(s.sseClients, clientID)
		close(clientChan)
		s.mu.Unlock()
		s.logger.Debug("SSE client disconnected", zap.String("clientID", clientID))
	}()

	// Send initial connection event
	fmt.Fprintf(w, "event: connected\ndata: {\"clientId\":\"%s\"}\n\n", clientID)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Stream events
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-clientChan:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

// BroadcastEvent sends an event to all connected SSE clients.
func (s *Server) BroadcastEvent(eventType string, data interface{}) {
	payload, err := json.Marshal(map[string]interface{}{
		"type": eventType,
		"data": data,
	})
	if err != nil {
		s.logger.Error("Failed to marshal broadcast event", zap.Error(err))
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for clientID, ch := range s.sseClients {
		select {
		case ch <- payload:
		default:
			s.logger.Warn("SSE client buffer full, dropping event", zap.String("clientID", clientID))
		}
	}
}

// handleToolsList returns the list of available tools.
func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tools := []map[string]interface{}{
		{
			"name":        "potoo_query",
			"description": "Query constraints affecting a namespace or workload",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"namespace":           map[string]string{"type": "string", "description": "Namespace to query"},
					"workload_name":       map[string]string{"type": "string", "description": "Optional workload name filter"},
					"workload_labels":     map[string]string{"type": "object", "description": "Optional label selector"},
					"constraint_type":     map[string]string{"type": "string", "description": "Optional constraint type filter"},
					"severity":            map[string]string{"type": "string", "description": "Optional severity filter"},
					"include_remediation": map[string]string{"type": "boolean", "description": "Include remediation steps"},
				},
				"required": []string{"namespace"},
			},
		},
		{
			"name":        "potoo_explain",
			"description": "Explain which constraint caused a specific error",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"error_message": map[string]string{"type": "string", "description": "Error message to analyze"},
					"namespace":     map[string]string{"type": "string", "description": "Namespace context"},
					"workload_name": map[string]string{"type": "string", "description": "Optional workload name"},
				},
				"required": []string{"error_message", "namespace"},
			},
		},
		{
			"name":        "potoo_check",
			"description": "Pre-check whether a manifest would be blocked",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"manifest": map[string]string{"type": "string", "description": "YAML manifest to check"},
				},
				"required": []string{"manifest"},
			},
		},
		{
			"name":        "potoo_list_namespaces",
			"description": "List all namespaces with constraint summaries",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "potoo_remediation",
			"description": "Get detailed remediation for a specific constraint",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint_name": map[string]string{"type": "string", "description": "Name of the constraint"},
					"namespace":       map[string]string{"type": "string", "description": "Namespace of the constraint"},
				},
				"required": []string{"constraint_name", "namespace"},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tools": tools})
}

// handleResourcesList returns the list of available resources.
func (s *Server) handleResourcesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resources := []map[string]interface{}{
		{
			"uri":         "potoo://reports/{namespace}",
			"name":        "Constraint Report",
			"description": "Full ConstraintReport for a namespace",
			"mimeType":    "application/json",
		},
		{
			"uri":         "potoo://constraints/{namespace}/{name}",
			"name":        "Constraint Detail",
			"description": "Single constraint details",
			"mimeType":    "application/json",
		},
		{
			"uri":         "potoo://health",
			"name":        "Health Status",
			"description": "Operational health of Potoo",
			"mimeType":    "application/json",
		},
		{
			"uri":         "potoo://capabilities",
			"name":        "Capabilities",
			"description": "What this Potoo instance can do",
			"mimeType":    "application/json",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"resources": resources})
}

// OnIndexChange is called when the constraint index changes.
// It broadcasts updates to connected SSE clients.
func (s *Server) OnIndexChange(event indexer.IndexEvent) {
	s.BroadcastEvent("constraint_change", map[string]interface{}{
		"type":           event.Type,
		"constraintUID":  string(event.Constraint.UID),
		"constraintName": event.Constraint.Name,
		"namespace":      event.Constraint.Namespace,
		"constraintType": string(event.Constraint.ConstraintType),
		"severity":       string(event.Constraint.Severity),
	})
}
