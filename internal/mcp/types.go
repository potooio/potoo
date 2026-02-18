package mcp

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
)

// --- Tool: potoo_query ---

type QueryParams struct {
	Namespace          string            `json:"namespace"`
	WorkloadName       string            `json:"workload_name,omitempty"`
	WorkloadLabels     map[string]string `json:"workload_labels,omitempty"`
	ConstraintType     string            `json:"constraint_type,omitempty"`
	Severity           string            `json:"severity,omitempty"`
	IncludeRemediation bool              `json:"include_remediation"`
}

type QueryResult struct {
	Namespace   string             `json:"namespace"`
	Constraints []ConstraintResult `json:"constraints"`
	Total       int                `json:"total"`
}

type ConstraintResult struct {
	Name              string                 `json:"name"`
	Namespace         string                 `json:"namespace,omitempty"`
	ConstraintType    string                 `json:"constraint_type"`
	Severity          string                 `json:"severity"`
	SourceKind        string                 `json:"source_kind"`
	SourceAPIVersion  string                 `json:"source_api_version"`
	Effect            string                 `json:"effect"`
	AffectedWorkloads []string               `json:"affected_workloads,omitempty"`
	Remediation       *RemediationResult     `json:"remediation,omitempty"`
	Metrics           map[string]MetricValue `json:"metrics,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	DetailLevel       string                 `json:"detail_level"`
	LastObserved      string                 `json:"last_observed"`
}

// --- Tool: potoo_explain ---

type ExplainParams struct {
	ErrorMessage string `json:"error_message"`
	Namespace    string `json:"namespace"`
	WorkloadName string `json:"workload_name,omitempty"`
}

type ExplainResult struct {
	Explanation         string             `json:"explanation"`
	MatchingConstraints []ConstraintResult `json:"matching_constraints"`
	Confidence          string             `json:"confidence"` // high, medium, low
	RemediationSteps    []RemediationStep  `json:"remediation_steps,omitempty"`
}

// --- Tool: potoo_check ---

type CheckParams struct {
	Manifest string `json:"manifest"` // YAML
}

type CheckResult struct {
	WouldBlock           bool               `json:"would_block"`
	BlockingConstraints  []ConstraintResult `json:"blocking_constraints,omitempty"`
	MissingPrerequisites []MissingResource  `json:"missing_prerequisites,omitempty"`
	Warnings             []string           `json:"warnings,omitempty"`
}

// --- Tool: potoo_list_namespaces ---

type NamespaceSummary struct {
	Namespace     string `json:"namespace"`
	Total         int    `json:"total"`
	CriticalCount int    `json:"critical_count"`
	WarningCount  int    `json:"warning_count"`
	InfoCount     int    `json:"info_count"`
	TopConstraint string `json:"top_constraint,omitempty"` // highest severity constraint name
}

// --- Tool: potoo_remediation ---

type RemediationParams struct {
	ConstraintName string `json:"constraint_name"`
	Namespace      string `json:"namespace"`
}

type RemediationResult struct {
	Summary string            `json:"summary"`
	Steps   []RemediationStep `json:"steps"`
}

type RemediationStep struct {
	Type              string `json:"type"` // manual, kubectl, annotation, yaml_patch, link
	Description       string `json:"description"`
	Command           string `json:"command,omitempty"`
	Patch             string `json:"patch,omitempty"`
	Template          string `json:"template,omitempty"`
	URL               string `json:"url,omitempty"`
	Contact           string `json:"contact,omitempty"`
	RequiresPrivilege string `json:"requires_privilege,omitempty"` // developer, namespace-admin, cluster-admin
	Automated         bool   `json:"automated"`
}

// --- Resource: potoo://health ---

type HealthResponse struct {
	Status   string                   `json:"status"` // healthy, degraded, unhealthy
	Adapters map[string]AdapterHealth `json:"adapters"`
	Hubble   *HubbleHealth            `json:"hubble,omitempty"`
	MCP      MCPHealth                `json:"mcp"`
	Indexer  IndexerHealth            `json:"indexer"`
	LastScan string                   `json:"last_scan"`
}

type AdapterHealth struct {
	Enabled          bool   `json:"enabled"`
	WatchedResources int    `json:"watched_resources"`
	ErrorCount       int    `json:"error_count"`
	Reason           string `json:"reason,omitempty"` // why disabled (e.g., "CRDs not installed")
}

type HubbleHealth struct {
	Enabled   bool   `json:"enabled"`
	Connected bool   `json:"connected"`
	Address   string `json:"address,omitempty"`
}

type MCPHealth struct {
	Enabled   bool   `json:"enabled"`
	Transport string `json:"transport"`
	Port      int    `json:"port"`
}

type IndexerHealth struct {
	TotalConstraints          int `json:"total_constraints"`
	NamespacesWithConstraints int `json:"namespaces_with_constraints"`
}

// --- Shared types ---

type MissingResource struct {
	ExpectedKind       string             `json:"expected_kind"`
	ExpectedAPIVersion string             `json:"expected_api_version"`
	Reason             string             `json:"reason"`
	Severity           string             `json:"severity"`
	ForWorkload        string             `json:"for_workload"`
	Remediation        *RemediationResult `json:"remediation,omitempty"`
}

type MetricValue struct {
	Hard        string  `json:"hard"`
	Used        string  `json:"used"`
	Unit        string  `json:"unit"`
	PercentUsed float64 `json:"percent_used"`
}

// ToConstraintResult converts an internal Constraint to an MCP-friendly result.
// Applies privacy scoping based on detailLevel.
func ToConstraintResult(c types.Constraint, detailLevel types.DetailLevel, viewerNamespace string) ConstraintResult {
	result := ConstraintResult{
		ConstraintType: string(c.ConstraintType),
		Severity:       string(c.Severity),
		Effect:         c.Effect,
		Tags:           c.Tags,
		DetailLevel:    string(detailLevel),
		LastObserved:   time.Now().UTC().Format(time.RFC3339),
	}

	// Apply privacy scoping to name
	result.Name = scopedConstraintName(c, detailLevel, viewerNamespace)

	// Apply privacy scoping to namespace
	if canShowNamespace(c, detailLevel, viewerNamespace) {
		result.Namespace = c.Namespace
	}

	// Source info
	result.SourceKind = gvrToKind(c.Source)
	result.SourceAPIVersion = gvrToAPIVersion(c.Source)

	// Extract metrics for resource constraints at detailed+ level
	if c.ConstraintType == types.ConstraintTypeResourceLimit {
		if detailLevel == types.DetailLevelDetailed || detailLevel == types.DetailLevelFull {
			result.Metrics = extractMetrics(c)
		}
	}

	return result
}

// ToConstraintResultWithRemediation includes remediation info in the result.
func ToConstraintResultWithRemediation(c types.Constraint, detailLevel types.DetailLevel, viewerNamespace string, remediationBuilder RemediationBuilder) ConstraintResult {
	result := ToConstraintResult(c, detailLevel, viewerNamespace)

	remediation := remediationBuilder(c)
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

// RemediationBuilder is a function that builds remediation info from a constraint.
type RemediationBuilder func(c types.Constraint) RemediationInfo

// RemediationInfo is used internally for building remediation.
type RemediationInfo struct {
	Summary string
	Steps   []RemediationStepInfo
}

// RemediationStepInfo is the internal step representation.
type RemediationStepInfo struct {
	Type              string
	Description       string
	Command           string
	Patch             string
	Template          string
	URL               string
	Contact           string
	RequiresPrivilege string
}

// scopedConstraintName returns the constraint name based on privacy level.
func scopedConstraintName(c types.Constraint, level types.DetailLevel, viewerNamespace string) string {
	if level == types.DetailLevelSummary {
		if c.Namespace == "" || c.Namespace != viewerNamespace {
			return "redacted"
		}
	}
	return c.Name
}

// canShowNamespace returns true if the constraint namespace can be shown.
func canShowNamespace(c types.Constraint, level types.DetailLevel, viewerNamespace string) bool {
	if level == types.DetailLevelSummary {
		return c.Namespace == viewerNamespace
	}
	if level == types.DetailLevelDetailed {
		return c.Namespace == "" || c.Namespace == viewerNamespace
	}
	return true
}

// gvrToKind converts a GVR resource name to a Kind name.
func gvrToKind(gvr schema.GroupVersionResource) string {
	switch gvr.Resource {
	case "networkpolicies":
		return "NetworkPolicy"
	case "resourcequotas":
		return "ResourceQuota"
	case "limitranges":
		return "LimitRange"
	case "validatingwebhookconfigurations":
		return "ValidatingWebhookConfiguration"
	case "mutatingwebhookconfigurations":
		return "MutatingWebhookConfiguration"
	case "ciliumnetworkpolicies":
		return "CiliumNetworkPolicy"
	case "ciliumclusterwidenetworkpolicies":
		return "CiliumClusterwideNetworkPolicy"
	default:
		// Generic handling
		resource := gvr.Resource
		if len(resource) > 1 && resource[len(resource)-1] == 's' {
			resource = resource[:len(resource)-1]
		}
		if len(resource) > 0 {
			return string(resource[0]-32) + resource[1:]
		}
		return resource
	}
}

// gvrToAPIVersion converts a GVR to an API version string.
func gvrToAPIVersion(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return gvr.Version
	}
	return fmt.Sprintf("%s/%s", gvr.Group, gvr.Version)
}

// extractMetrics extracts resource metrics from constraint details.
func extractMetrics(c types.Constraint) map[string]MetricValue {
	if c.Details == nil {
		return nil
	}

	resources, ok := c.Details["resources"].(map[string]interface{})
	if !ok {
		return nil
	}

	metrics := make(map[string]MetricValue)
	for name, infoRaw := range resources {
		info, ok := infoRaw.(map[string]interface{})
		if !ok {
			continue
		}

		metric := MetricValue{
			Unit: guessUnit(name),
		}

		if hard, ok := info["hard"].(string); ok {
			metric.Hard = hard
		}
		if used, ok := info["used"].(string); ok {
			metric.Used = used
		}
		if percent, ok := info["percent"].(int); ok {
			metric.PercentUsed = float64(percent)
		} else if percentFloat, ok := info["percent"].(float64); ok {
			metric.PercentUsed = percentFloat
		}

		metrics[name] = metric
	}

	return metrics
}

// guessUnit returns the unit for a resource name.
func guessUnit(resourceName string) string {
	switch {
	case resourceName == "cpu" || strings.HasSuffix(resourceName, ".cpu"):
		return "cores"
	case resourceName == "memory" || strings.HasSuffix(resourceName, ".memory"):
		return "bytes"
	case strings.Contains(resourceName, "storage"):
		return "bytes"
	default:
		return "count"
	}
}
