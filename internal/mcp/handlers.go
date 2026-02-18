package mcp

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/notifier"
	"github.com/potooio/potoo/internal/requirements"
	"github.com/potooio/potoo/internal/types"
)

// Handlers implements the MCP tool and resource handlers.
type Handlers struct {
	logger             *zap.Logger
	indexer            *indexer.Indexer
	privacyResolver    PrivacyResolverFunc
	remediationBuilder *notifier.RemediationBuilder
	evaluator          *requirements.Evaluator
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	idx *indexer.Indexer,
	privacyResolver PrivacyResolverFunc,
	defaultContact string,
	logger *zap.Logger,
	evaluator *requirements.Evaluator,
) *Handlers {
	return &Handlers{
		logger:             logger.Named("mcp-handlers"),
		indexer:            idx,
		privacyResolver:    privacyResolver,
		remediationBuilder: notifier.NewRemediationBuilder(defaultContact),
		evaluator:          evaluator,
	}
}

// HandleQuery handles the potoo_query tool.
func (h *Handlers) HandleQuery(w http.ResponseWriter, r *http.Request) {
	var params QueryParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if params.Namespace == "" {
		h.writeError(w, "namespace is required", http.StatusBadRequest)
		return
	}

	detailLevel := h.privacyResolver(r)

	// Query constraints
	var constraints []types.Constraint
	if len(params.WorkloadLabels) > 0 {
		constraints = h.indexer.ByLabels(params.Namespace, params.WorkloadLabels)
	} else {
		constraints = h.indexer.ByNamespace(params.Namespace)
	}

	// Apply filters
	constraints = h.filterConstraints(constraints, params)

	// Convert to results
	results := make([]ConstraintResult, 0, len(constraints))
	for _, c := range constraints {
		var result ConstraintResult
		if params.IncludeRemediation {
			result = h.toConstraintResultWithRemediation(c, detailLevel, params.Namespace)
		} else {
			result = ToConstraintResult(c, detailLevel, params.Namespace)
		}
		results = append(results, result)
	}

	// Sort by severity
	sort.Slice(results, func(i, j int) bool {
		return severityOrder(results[i].Severity) < severityOrder(results[j].Severity)
	})

	response := QueryResult{
		Namespace:   params.Namespace,
		Constraints: results,
		Total:       len(results),
	}

	h.writeJSON(w, response)
}

// HandleExplain handles the potoo_explain tool.
func (h *Handlers) HandleExplain(w http.ResponseWriter, r *http.Request) {
	var params ExplainParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if params.ErrorMessage == "" || params.Namespace == "" {
		h.writeError(w, "error_message and namespace are required", http.StatusBadRequest)
		return
	}

	detailLevel := h.privacyResolver(r)

	// Get constraints for namespace
	constraints := h.indexer.ByNamespace(params.Namespace)

	// Try to match error message to constraints
	matchingConstraints, confidence, explanation := h.matchErrorToConstraints(
		params.ErrorMessage,
		constraints,
		params.WorkloadName,
	)

	// Convert to results
	results := make([]ConstraintResult, 0, len(matchingConstraints))
	var remediationSteps []RemediationStep

	for _, c := range matchingConstraints {
		result := h.toConstraintResultWithRemediation(c, detailLevel, params.Namespace)
		results = append(results, result)

		// Collect remediation steps
		if result.Remediation != nil {
			remediationSteps = append(remediationSteps, result.Remediation.Steps...)
		}
	}

	response := ExplainResult{
		Explanation:         explanation,
		MatchingConstraints: results,
		Confidence:          confidence,
		RemediationSteps:    remediationSteps,
	}

	h.writeJSON(w, response)
}

// HandleCheck handles the potoo_check tool.
func (h *Handlers) HandleCheck(w http.ResponseWriter, r *http.Request) {
	var params CheckParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if params.Manifest == "" {
		h.writeError(w, "manifest is required", http.StatusBadRequest)
		return
	}

	detailLevel := h.privacyResolver(r)

	// Parse the manifest
	var manifest map[string]interface{}
	if err := yaml.Unmarshal([]byte(params.Manifest), &manifest); err != nil {
		h.writeError(w, "Invalid YAML manifest", http.StatusBadRequest)
		return
	}

	// Extract namespace and labels
	metadata, _ := manifest["metadata"].(map[string]interface{})
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = "default"
	}

	labels, _ := metadata["labels"].(map[string]interface{})
	labelMap := make(map[string]string)
	for k, v := range labels {
		if strVal, ok := v.(string); ok {
			labelMap[k] = strVal
		}
	}

	// Check for blocking constraints
	constraints := h.indexer.ByLabels(namespace, labelMap)

	var blockingConstraints []ConstraintResult
	var warnings []string

	for _, c := range constraints {
		result := ToConstraintResult(c, detailLevel, namespace)

		// Consider critical admission constraints as blocking
		if c.ConstraintType == types.ConstraintTypeAdmission && c.Severity == types.SeverityCritical {
			blockingConstraints = append(blockingConstraints, result)
		} else if c.Severity == types.SeverityWarning {
			warnings = append(warnings, result.Name+": "+genericSummary(c.ConstraintType))
		}
	}

	// Evaluate missing prerequisites if evaluator is available.
	var missingPrereqs []MissingResource
	if h.evaluator != nil {
		workloadObj := &unstructured.Unstructured{Object: manifest}
		missingConstraints, err := h.evaluator.Evaluate(r.Context(), workloadObj)
		if err != nil {
			h.logger.Warn("Failed to evaluate missing prerequisites", zap.Error(err))
		}
		for _, mc := range missingConstraints {
			missingPrereqs = append(missingPrereqs, constraintToMissingResource(mc, workloadObj, h.remediationBuilder))
		}
	}
	if missingPrereqs == nil {
		missingPrereqs = []MissingResource{}
	}

	response := CheckResult{
		WouldBlock:           len(blockingConstraints) > 0,
		BlockingConstraints:  blockingConstraints,
		MissingPrerequisites: missingPrereqs,
		Warnings:             warnings,
	}

	h.writeJSON(w, response)
}

// HandleListNamespaces handles the potoo_list_namespaces tool.
func (h *Handlers) HandleListNamespaces(w http.ResponseWriter, r *http.Request) {
	// Get all constraints and group by namespace
	allConstraints := h.indexer.All()

	nsMap := make(map[string][]types.Constraint)
	for _, c := range allConstraints {
		for _, ns := range c.AffectedNamespaces {
			nsMap[ns] = append(nsMap[ns], c)
		}
		if c.Namespace != "" {
			nsMap[c.Namespace] = append(nsMap[c.Namespace], c)
		}
	}

	var summaries []NamespaceSummary
	for ns, constraints := range nsMap {
		// Deduplicate by UID
		seen := make(map[string]bool)
		var unique []types.Constraint
		for _, c := range constraints {
			if !seen[string(c.UID)] {
				seen[string(c.UID)] = true
				unique = append(unique, c)
			}
		}

		summary := NamespaceSummary{
			Namespace: ns,
			Total:     len(unique),
		}

		var topSeverity types.Severity
		for _, c := range unique {
			switch c.Severity {
			case types.SeverityCritical:
				summary.CriticalCount++
				if topSeverity == "" {
					topSeverity = c.Severity
					summary.TopConstraint = c.Name
				}
			case types.SeverityWarning:
				summary.WarningCount++
				if topSeverity == "" || topSeverity == types.SeverityInfo {
					topSeverity = c.Severity
					summary.TopConstraint = c.Name
				}
			case types.SeverityInfo:
				summary.InfoCount++
				if topSeverity == "" {
					topSeverity = c.Severity
					summary.TopConstraint = c.Name
				}
			}
		}

		summaries = append(summaries, summary)
	}

	// Sort by namespace name
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Namespace < summaries[j].Namespace
	})

	h.writeJSON(w, summaries)
}

// HandleRemediation handles the potoo_remediation tool.
func (h *Handlers) HandleRemediation(w http.ResponseWriter, r *http.Request) {
	var params RemediationParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if params.ConstraintName == "" || params.Namespace == "" {
		h.writeError(w, "constraint_name and namespace are required", http.StatusBadRequest)
		return
	}

	// Find the constraint
	constraints := h.indexer.ByNamespace(params.Namespace)
	var target *types.Constraint
	for _, c := range constraints {
		if c.Name == params.ConstraintName {
			target = &c
			break
		}
	}

	if target == nil {
		h.writeError(w, "Constraint not found", http.StatusNotFound)
		return
	}

	// Build remediation
	remediation := h.remediationBuilder.Build(*target)

	response := RemediationResult{
		Summary: remediation.Summary,
	}

	for _, step := range remediation.Steps {
		response.Steps = append(response.Steps, RemediationStep{
			Type:              step.Type,
			Description:       step.Description,
			Command:           step.Command,
			Patch:             step.Patch,
			Template:          step.Template,
			URL:               step.URL,
			Contact:           step.Contact,
			RequiresPrivilege: step.RequiresPrivilege,
			Automated:         step.Type == "kubectl" || step.Type == "annotation",
		})
	}

	h.writeJSON(w, response)
}

// HandleReportResource handles the reports/{namespace} resource.
func (h *Handlers) HandleReportResource(w http.ResponseWriter, r *http.Request) {
	// Extract namespace from path
	path := strings.TrimPrefix(r.URL.Path, "/resources/reports/")
	namespace := strings.TrimSuffix(path, "/")

	if namespace == "" {
		h.writeError(w, "Namespace is required", http.StatusBadRequest)
		return
	}

	detailLevel := h.privacyResolver(r)

	// Build report from indexer
	constraints := h.indexer.ByNamespace(namespace)

	report := h.buildReport(constraints, namespace, detailLevel)
	h.writeJSON(w, report)
}

// HandleConstraintResource handles the constraints/{namespace}/{name} resource.
func (h *Handlers) HandleConstraintResource(w http.ResponseWriter, r *http.Request) {
	// Extract namespace and name from path
	path := strings.TrimPrefix(r.URL.Path, "/resources/constraints/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) < 2 {
		h.writeError(w, "Namespace and constraint name are required", http.StatusBadRequest)
		return
	}

	namespace := parts[0]
	name := parts[1]

	detailLevel := h.privacyResolver(r)

	// Find the constraint
	constraints := h.indexer.ByNamespace(namespace)
	for _, c := range constraints {
		if c.Name == name {
			result := h.toConstraintResultWithRemediation(c, detailLevel, namespace)
			h.writeJSON(w, result)
			return
		}
	}

	h.writeError(w, "Constraint not found", http.StatusNotFound)
}

// HandleHealthResource handles the health resource.
func (h *Handlers) HandleHealthResource(w http.ResponseWriter, r *http.Request) {
	allConstraints := h.indexer.All()

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

	response := HealthResponse{
		Status: "healthy",
		Adapters: map[string]AdapterHealth{
			"networkpolicy": {Enabled: true, WatchedResources: 1},
			"resourcequota": {Enabled: true, WatchedResources: 1},
			"limitrange":    {Enabled: true, WatchedResources: 1},
			"webhookconfig": {Enabled: true, WatchedResources: 2},
			"generic":       {Enabled: true, WatchedResources: 0},
		},
		MCP: MCPHealth{
			Enabled:   true,
			Transport: "sse",
			Port:      8090,
		},
		Indexer: IndexerHealth{
			TotalConstraints:          len(allConstraints),
			NamespacesWithConstraints: len(nsSet),
		},
		LastScan: time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, response)
}

// HandleCapabilitiesResource handles the capabilities resource.
func (h *Handlers) HandleCapabilitiesResource(w http.ResponseWriter, r *http.Request) {
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

	response := map[string]interface{}{
		"version": "1",
		"adapters": []string{
			"networkpolicy",
			"resourcequota",
			"limitrange",
			"webhookconfig",
			"generic",
		},
		"constraintTypes":  typeCount,
		"totalConstraints": len(allConstraints),
		"namespaceCount":   len(nsSet),
		"hubbleEnabled":    false,
		"mcpEnabled":       true,
		"lastScan":         time.Now().UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, response)
}

// filterConstraints filters constraints based on query parameters.
func (h *Handlers) filterConstraints(constraints []types.Constraint, params QueryParams) []types.Constraint {
	var result []types.Constraint

	for _, c := range constraints {
		// Filter by constraint type
		if params.ConstraintType != "" && string(c.ConstraintType) != params.ConstraintType {
			continue
		}

		// Filter by severity
		if params.Severity != "" && string(c.Severity) != params.Severity {
			continue
		}

		result = append(result, c)
	}

	return result
}

// matchErrorToConstraints tries to match an error message to relevant constraints.
func (h *Handlers) matchErrorToConstraints(
	errorMessage string,
	constraints []types.Constraint,
	workloadName string,
) ([]types.Constraint, string, string) {
	errorLower := strings.ToLower(errorMessage)

	var matches []types.Constraint
	confidence := "low"
	explanation := "No matching constraints found for this error message."

	// Network-related errors
	networkPatterns := []string{
		"connection refused", "connection timed out", "network unreachable",
		"no route to host", "dial tcp", "i/o timeout", "egress", "ingress",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(errorLower, pattern) {
			for _, c := range constraints {
				if c.ConstraintType == types.ConstraintTypeNetworkIngress ||
					c.ConstraintType == types.ConstraintTypeNetworkEgress {
					matches = append(matches, c)
				}
			}
			if len(matches) > 0 {
				confidence = "high"
				explanation = "This error appears to be network-related. The following network policies may be blocking traffic."
			}
			break
		}
	}

	// Admission-related errors
	admissionPatterns := []string{
		"denied", "rejected", "forbidden", "admission", "webhook",
		"not allowed", "policy violation", "constraint",
	}
	if len(matches) == 0 {
		for _, pattern := range admissionPatterns {
			if strings.Contains(errorLower, pattern) {
				for _, c := range constraints {
					if c.ConstraintType == types.ConstraintTypeAdmission {
						matches = append(matches, c)
					}
				}
				if len(matches) > 0 {
					confidence = "high"
					explanation = "This error appears to be from an admission controller. The following admission policies may be rejecting the request."
				}
				break
			}
		}
	}

	// Resource quota errors
	quotaPatterns := []string{
		"exceeded quota", "resource quota", "limit exceeded", "insufficient",
		"cpu", "memory", "storage",
	}
	if len(matches) == 0 {
		for _, pattern := range quotaPatterns {
			if strings.Contains(errorLower, pattern) {
				for _, c := range constraints {
					if c.ConstraintType == types.ConstraintTypeResourceLimit {
						matches = append(matches, c)
					}
				}
				if len(matches) > 0 {
					confidence = "high"
					explanation = "This error appears to be quota-related. The following resource quotas may be limiting resources."
				}
				break
			}
		}
	}

	// If still no matches, return all constraints as low confidence
	if len(matches) == 0 {
		matches = constraints
		confidence = "low"
		explanation = "Could not determine the specific cause. Here are all constraints in the namespace that might be relevant."
	}

	return matches, confidence, explanation
}

// toConstraintResultWithRemediation converts a constraint to a result with remediation.
func (h *Handlers) toConstraintResultWithRemediation(c types.Constraint, detailLevel types.DetailLevel, namespace string) ConstraintResult {
	result := ToConstraintResult(c, detailLevel, namespace)

	remediation := h.remediationBuilder.Build(c)
	result.Remediation = &RemediationResult{
		Summary: remediation.Summary,
	}

	for _, step := range remediation.Steps {
		result.Remediation.Steps = append(result.Remediation.Steps, RemediationStep{
			Type:              step.Type,
			Description:       step.Description,
			Command:           step.Command,
			Patch:             step.Patch,
			Template:          step.Template,
			URL:               step.URL,
			Contact:           step.Contact,
			RequiresPrivilege: step.RequiresPrivilege,
			Automated:         step.Type == "kubectl" || step.Type == "annotation",
		})
	}

	return result
}

// buildReport builds a report structure from constraints.
func (h *Handlers) buildReport(constraints []types.Constraint, namespace string, detailLevel types.DetailLevel) map[string]interface{} {
	var criticalCount, warningCount, infoCount int
	var entries []map[string]interface{}

	for _, c := range constraints {
		switch c.Severity {
		case types.SeverityCritical:
			criticalCount++
		case types.SeverityWarning:
			warningCount++
		case types.SeverityInfo:
			infoCount++
		}

		result := h.toConstraintResultWithRemediation(c, detailLevel, namespace)
		entries = append(entries, map[string]interface{}{
			"name":        result.Name,
			"type":        result.ConstraintType,
			"severity":    result.Severity,
			"effect":      result.Effect,
			"source":      result.SourceKind,
			"remediation": result.Remediation,
			"tags":        result.Tags,
		})
	}

	return map[string]interface{}{
		"namespace":       namespace,
		"constraintCount": len(constraints),
		"criticalCount":   criticalCount,
		"warningCount":    warningCount,
		"infoCount":       infoCount,
		"constraints":     entries,
		"schemaVersion":   "1",
		"detailLevel":     string(detailLevel),
		"generatedAt":     time.Now().UTC().Format(time.RFC3339),
	}
}

// writeJSON writes a JSON response.
func (h *Handlers) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// writeError writes an error response.
func (h *Handlers) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// severityOrder returns a sort order for severities (lower = more severe).
func severityOrder(severity string) int {
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

// constraintToMissingResource converts a ConstraintTypeMissing constraint to an MCP MissingResource.
func constraintToMissingResource(c types.Constraint, workload *unstructured.Unstructured, rb *notifier.RemediationBuilder) MissingResource {
	mr := MissingResource{
		Severity: string(c.Severity),
	}

	// Extract workload identity from the workload object itself (not the constraint).
	if workload != nil {
		kind := workload.GetKind()
		name := workload.GetName()
		ns := workload.GetNamespace()
		if ns != "" {
			mr.ForWorkload = ns + "/" + kind + "/" + name
		} else {
			mr.ForWorkload = kind + "/" + name
		}
	}

	if c.Details != nil {
		if v, ok := c.Details["expectedKind"].(string); ok {
			mr.ExpectedKind = v
		}
		if v, ok := c.Details["expectedAPIVersion"].(string); ok {
			mr.ExpectedAPIVersion = v
		}
		if v, ok := c.Details["reason"].(string); ok {
			mr.Reason = v
		}
	}

	if rb != nil {
		remediation := rb.Build(c)
		mr.Remediation = &RemediationResult{
			Summary: remediation.Summary,
		}
		for _, step := range remediation.Steps {
			mr.Remediation.Steps = append(mr.Remediation.Steps, RemediationStep{
				Type:              step.Type,
				Description:       step.Description,
				Command:           step.Command,
				Patch:             step.Patch,
				Template:          step.Template,
				URL:               step.URL,
				Contact:           step.Contact,
				RequiresPrivilege: step.RequiresPrivilege,
				Automated:         step.Type == "kubectl" || step.Type == "annotation",
			})
		}
	}

	return mr
}

// genericSummary returns a generic summary for a constraint type.
func genericSummary(ct types.ConstraintType) string {
	switch ct {
	case types.ConstraintTypeNetworkIngress:
		return "Inbound network traffic is restricted"
	case types.ConstraintTypeNetworkEgress:
		return "Outbound network traffic is restricted"
	case types.ConstraintTypeAdmission:
		return "An admission policy may reject resources"
	case types.ConstraintTypeResourceLimit:
		return "Resource quotas or limits apply"
	case types.ConstraintTypeMeshPolicy:
		return "Service mesh policies apply"
	case types.ConstraintTypeMissing:
		return "A required resource may be missing"
	default:
		return "A policy constraint applies"
	}
}
