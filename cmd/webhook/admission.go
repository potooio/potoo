package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/potooio/potoo/internal/types"
)

var (
	scheme       = runtime.NewScheme()
	codecs       = serializer.NewCodecFactory(scheme)
	deserializer = codecs.UniversalDeserializer()
)

func init() {
	_ = admissionv1.AddToScheme(scheme)
}

// AdmissionHandler handles admission review requests.
type AdmissionHandler struct {
	client ConstraintQuerier
	logger *zap.Logger
}

// ConstraintQuerier queries constraints from the controller.
type ConstraintQuerier interface {
	Query(ctx context.Context, namespace string, labels map[string]string) ([]types.Constraint, error)
}

// NewAdmissionHandler creates a new admission handler.
func NewAdmissionHandler(client ConstraintQuerier, logger *zap.Logger) *AdmissionHandler {
	return &AdmissionHandler{
		client: client,
		logger: logger.Named("admission"),
	}
}

// Handle handles an admission review request.
func (h *AdmissionHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Limit body size to prevent DoS (typical admission review is ~10-50KB)
	const maxBodySize = 1 << 20 // 1MB
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		h.logger.Error("Failed to read request body", zap.Error(err))
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Decode the AdmissionReview
	review := &admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, review); err != nil {
		h.logger.Error("Failed to decode admission review", zap.Error(err))
		h.sendResponse(w, &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Message: "Failed to decode request, allowing by default",
				},
			},
		})
		return
	}

	// Process the request
	response := h.processRequest(r.Context(), review.Request)
	review.Response = response

	h.sendResponse(w, review)
}

// processRequest processes an admission request and returns a response.
// IMPORTANT: This webhook NEVER rejects requests. It only returns warnings.
func (h *AdmissionHandler) processRequest(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true, // NEVER reject
	}

	// Extract namespace and labels from the request
	namespace := req.Namespace
	labels := extractLabels(req)

	h.logger.Debug("Processing admission request",
		zap.String("uid", string(req.UID)),
		zap.String("namespace", namespace),
		zap.String("kind", req.Kind.Kind),
		zap.String("name", req.Name),
		zap.String("operation", string(req.Operation)),
	)

	// Query constraints with a timeout
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	constraints, err := h.client.Query(queryCtx, namespace, labels)
	if err != nil {
		h.logger.Error("Failed to query constraints", zap.Error(err))
		// On error, allow the request (fail-open)
		return response
	}

	// Build warnings from relevant constraints
	warnings := h.buildWarnings(req, constraints)
	if len(warnings) > 0 {
		response.Warnings = warnings
		h.logger.Info("Returning constraint warnings",
			zap.String("uid", string(req.UID)),
			zap.Int("warning_count", len(warnings)),
		)
	}

	return response
}

// extractLabels extracts labels from the admission request object.
func extractLabels(req *admissionv1.AdmissionRequest) map[string]string {
	if req.Object.Raw == nil {
		return nil
	}

	// Parse the object to extract labels
	var obj struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		return nil
	}

	return obj.Metadata.Labels
}

// buildWarnings creates warning messages from matching constraints.
func (h *AdmissionHandler) buildWarnings(req *admissionv1.AdmissionRequest, constraints []types.Constraint) []string {
	var warnings []string

	for _, c := range constraints {
		// Only include warnings for constraints with Warning or Critical severity
		if c.Severity != types.SeverityWarning && c.Severity != types.SeverityCritical {
			continue
		}

		// Check if this constraint applies to the requested resource type
		if !h.constraintApplies(req, c) {
			continue
		}

		// Build the warning message
		warning := h.formatWarning(c)
		warnings = append(warnings, warning)
	}

	return warnings
}

// constraintApplies checks if a constraint applies to the given request.
func (h *AdmissionHandler) constraintApplies(req *admissionv1.AdmissionRequest, c types.Constraint) bool {
	// If no resource targets specified, assume it applies
	if len(c.ResourceTargets) == 0 {
		return true
	}

	reqGroup := req.Kind.Group
	reqResource := strings.ToLower(req.Kind.Kind) + "s" // Approximate pluralization

	for _, target := range c.ResourceTargets {
		// Check API groups
		groupMatches := len(target.APIGroups) == 0
		for _, g := range target.APIGroups {
			if g == "*" || g == reqGroup {
				groupMatches = true
				break
			}
		}

		if !groupMatches {
			continue
		}

		// Check resources
		for _, r := range target.Resources {
			if r == "*" || r == reqResource {
				return true
			}
		}
	}

	return false
}

// formatWarning formats a constraint as a warning message.
func (h *AdmissionHandler) formatWarning(c types.Constraint) string {
	severityPrefix := "[WARNING]"
	if c.Severity == types.SeverityCritical {
		severityPrefix = "[CRITICAL]"
	}

	return fmt.Sprintf("%s %s - %s",
		severityPrefix,
		c.Summary,
		c.RemediationHint,
	)
}

// sendResponse sends an admission review response.
func (h *AdmissionHandler) sendResponse(w http.ResponseWriter, review *admissionv1.AdmissionReview) {
	review.TypeMeta = metav1.TypeMeta{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
	}

	responseBytes, err := json.Marshal(review)
	if err != nil {
		h.logger.Error("Failed to marshal response", zap.Error(err))
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

// ConstraintClient queries constraints from the Potoo controller.
type ConstraintClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewConstraintClient creates a new constraint client.
func NewConstraintClient(baseURL string, logger *zap.Logger) *ConstraintClient {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
	return &ConstraintClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		logger: logger.Named("constraint-client"),
	}
}

// Query queries constraints from the controller.
func (c *ConstraintClient) Query(ctx context.Context, namespace string, labels map[string]string) ([]types.Constraint, error) {
	queryURL := fmt.Sprintf("%s/api/v1/constraints?namespace=%s", c.baseURL, url.QueryEscape(namespace))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query controller: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("controller returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Constraints []types.Constraint `json:"constraints"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Constraints, nil
}
