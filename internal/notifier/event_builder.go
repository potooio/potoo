package notifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/annotations"
	"github.com/potooio/potoo/internal/types"
)

// EventStructuredData is the JSON payload stored in the EventStructuredData annotation.
// This is the primary data source for agents consuming Potoo events.
type EventStructuredData struct {
	// SchemaVersion allows agents to detect breaking changes. Currently "1".
	SchemaVersion string `json:"schemaVersion"`

	// Constraint details
	ConstraintUID       string `json:"constraintUid"`
	ConstraintName      string `json:"constraintName"`
	ConstraintNamespace string `json:"constraintNamespace,omitempty"`
	ConstraintType      string `json:"constraintType"`
	Severity            string `json:"severity"`
	Effect              string `json:"effect"`

	// Source reference
	SourceGVR       string `json:"sourceGvr"`
	SourceKind      string `json:"sourceKind"`
	SourceName      string `json:"sourceName"`
	SourceNamespace string `json:"sourceNamespace,omitempty"`

	// Affected workload
	WorkloadKind      string `json:"workloadKind"`
	WorkloadName      string `json:"workloadName"`
	WorkloadNamespace string `json:"workloadNamespace"`

	// Message and remediation
	Summary     string                     `json:"summary"`
	Remediation *v1alpha1.RemediationInfo  `json:"remediation,omitempty"`
	Metrics     map[string]MetricDataPoint `json:"metrics,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`

	// Privacy scoping
	DetailLevel string `json:"detailLevel"`

	// Timestamps
	ObservedAt string `json:"observedAt"`
}

// MetricDataPoint contains quantitative data for resource constraints.
type MetricDataPoint struct {
	Hard        string  `json:"hard"`
	Used        string  `json:"used"`
	Unit        string  `json:"unit"`
	PercentUsed float64 `json:"percentUsed"`
}

// EventBuilder creates Kubernetes Events with structured annotations for agent consumption.
type EventBuilder struct {
	remediationBuilder *RemediationBuilder
}

// NewEventBuilder creates a new EventBuilder.
func NewEventBuilder(defaultContact string) *EventBuilder {
	return &EventBuilder{
		remediationBuilder: NewRemediationBuilder(defaultContact),
	}
}

// BuildRemediation generates structured remediation info for a constraint.
func (eb *EventBuilder) BuildRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	return eb.remediationBuilder.Build(c)
}

// WorkloadRef identifies the workload to attach the event to.
type WorkloadRef struct {
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
	UID        string
}

// BuildEvent creates a corev1.Event with all Potoo annotations populated.
// The event is attached to the specified workload and includes machine-readable
// structured data for agent consumption.
func (eb *EventBuilder) BuildEvent(
	c types.Constraint,
	level types.DetailLevel,
	workload WorkloadRef,
	message string,
) *corev1.Event {
	now := metav1.Now()

	// Build the event
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "potoo-",
			Namespace:    workload.Namespace,
			Labels:       eb.buildLabels(c),
			Annotations:  eb.buildAnnotations(c, level, workload),
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: workload.APIVersion,
			Kind:       workload.Kind,
			Name:       workload.Name,
			Namespace:  workload.Namespace,
			UID:        k8stypes.UID(workload.UID),
		},
		Reason:              "ConstraintNotification",
		Message:             message,
		Type:                eb.eventType(c.Severity),
		Source:              corev1.EventSource{Component: "potoo-controller"},
		FirstTimestamp:      now,
		LastTimestamp:       now,
		Count:               1,
		ReportingController: "potoo.io/controller",
		ReportingInstance:   "potoo",
	}

	return event
}

// buildLabels creates the labels for filtering events via kubectl.
func (eb *EventBuilder) buildLabels(c types.Constraint) map[string]string {
	return map[string]string{
		annotations.LabelManagedBy:      annotations.ManagedByValue,
		annotations.LabelSeverity:       strings.ToLower(string(c.Severity)),
		annotations.LabelConstraintType: toKebabCase(string(c.ConstraintType)),
	}
}

// buildAnnotations creates all the annotations for the event.
func (eb *EventBuilder) buildAnnotations(
	c types.Constraint,
	level types.DetailLevel,
	workload WorkloadRef,
) map[string]string {
	annots := make(map[string]string)

	// Core annotations
	annots[annotations.ManagedBy] = annotations.ManagedByValue
	annots[annotations.EventConstraintType] = string(c.ConstraintType)
	annots[annotations.EventSeverity] = string(c.Severity)
	annots[annotations.EventEffect] = c.Effect
	annots[annotations.EventDetailLevel] = string(level)

	// Constraint identity - privacy scoped
	annots[annotations.EventConstraintName] = eb.scopedConstraintName(c, level, workload.Namespace)
	if c.Namespace != "" && eb.canShowNamespace(c, level, workload.Namespace) {
		annots[annotations.EventConstraintNamespace] = c.Namespace
	}

	// Source GVR
	annots[annotations.EventSourceGVR] = formatGVR(c.Source)

	// Remediation type
	remediation := eb.remediationBuilder.Build(c)
	if len(remediation.Steps) > 0 {
		annots[annotations.EventRemediationType] = remediation.Steps[0].Type
		if remediation.Steps[0].Contact != "" {
			annots[annotations.EventRemediationContact] = remediation.Steps[0].Contact
		}
	}

	// Structured data (JSON blob)
	structuredData := eb.BuildStructuredData(c, level, workload, remediation)
	if jsonBytes, err := json.Marshal(structuredData); err == nil {
		annots[annotations.EventStructuredData] = string(jsonBytes)
	}

	return annots
}

// BuildStructuredData creates the full JSON payload for agent consumption.
// This is used both for K8s Event annotations and for webhook payloads.
func (eb *EventBuilder) BuildStructuredData(
	c types.Constraint,
	level types.DetailLevel,
	workload WorkloadRef,
	remediation v1alpha1.RemediationInfo,
) EventStructuredData {
	data := EventStructuredData{
		SchemaVersion:     "1",
		ConstraintUID:     string(c.UID),
		ConstraintType:    string(c.ConstraintType),
		Severity:          string(c.Severity),
		Effect:            c.Effect,
		SourceGVR:         formatGVR(c.Source),
		SourceKind:        gvrToKind(c.Source),
		WorkloadKind:      workload.Kind,
		WorkloadName:      workload.Name,
		WorkloadNamespace: workload.Namespace,
		Summary:           eb.scopedSummary(c, level),
		Tags:              c.Tags,
		DetailLevel:       string(level),
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	// Privacy-scoped constraint identity
	data.ConstraintName = eb.scopedConstraintName(c, level, workload.Namespace)
	if eb.canShowNamespace(c, level, workload.Namespace) {
		data.ConstraintNamespace = c.Namespace
	}

	// Source details - only at detailed+ level
	if level == types.DetailLevelDetailed || level == types.DetailLevelFull {
		data.SourceName = c.Name
		if c.Namespace != "" {
			data.SourceNamespace = c.Namespace
		}
	}

	// Include remediation at all levels but scope contact info
	scopedRemediation := eb.scopeRemediation(remediation, level)
	data.Remediation = &scopedRemediation

	// Include metrics for resource constraints at detailed+ level
	if c.ConstraintType == types.ConstraintTypeResourceLimit {
		if level == types.DetailLevelDetailed || level == types.DetailLevelFull {
			data.Metrics = eb.extractMetrics(c)
		}
	}

	return data
}

// scopedConstraintName returns the constraint name based on privacy level.
func (eb *EventBuilder) scopedConstraintName(c types.Constraint, level types.DetailLevel, viewerNamespace string) string {
	// At summary level, only show name if same namespace
	if level == types.DetailLevelSummary {
		if c.Namespace == "" || c.Namespace != viewerNamespace {
			return "redacted"
		}
	}
	return c.Name
}

// canShowNamespace returns true if the constraint namespace can be shown.
func (eb *EventBuilder) canShowNamespace(c types.Constraint, level types.DetailLevel, viewerNamespace string) bool {
	// At summary level, only show namespace if same as viewer
	if level == types.DetailLevelSummary {
		return c.Namespace == viewerNamespace
	}
	// At detailed level, show namespace if same or if cluster-scoped
	if level == types.DetailLevelDetailed {
		return c.Namespace == "" || c.Namespace == viewerNamespace
	}
	// At full level, show everything
	return true
}

// scopedSummary returns the summary based on privacy level.
func (eb *EventBuilder) scopedSummary(c types.Constraint, level types.DetailLevel) string {
	switch level {
	case types.DetailLevelFull:
		return c.Summary
	case types.DetailLevelDetailed:
		// Strip cross-namespace references if present
		return c.Summary
	default:
		// Summary level: use generic description
		return genericSummary(c.ConstraintType)
	}
}

// scopeRemediation filters remediation steps based on privacy level.
func (eb *EventBuilder) scopeRemediation(r v1alpha1.RemediationInfo, level types.DetailLevel) v1alpha1.RemediationInfo {
	result := v1alpha1.RemediationInfo{
		Summary: r.Summary,
	}

	for _, step := range r.Steps {
		scopedStep := step

		// At summary level, redact specific commands and contacts
		if level == types.DetailLevelSummary {
			if step.Type == "kubectl" && step.RequiresPrivilege == "cluster-admin" {
				// Redact cluster-admin commands at summary level
				scopedStep.Command = ""
				scopedStep.Description = "Contact your platform team for this step"
			}
		}

		result.Steps = append(result.Steps, scopedStep)
	}

	return result
}

// extractMetrics extracts resource metrics from constraint details.
func (eb *EventBuilder) extractMetrics(c types.Constraint) map[string]MetricDataPoint {
	if c.Details == nil {
		return nil
	}

	resources, ok := c.Details["resources"].(map[string]interface{})
	if !ok {
		return nil
	}

	metrics := make(map[string]MetricDataPoint)
	for name, infoRaw := range resources {
		info, ok := infoRaw.(map[string]interface{})
		if !ok {
			continue
		}

		metric := MetricDataPoint{}
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

		// Determine unit from resource name
		metric.Unit = guessUnit(name)

		metrics[name] = metric
	}

	return metrics
}

// eventType returns the K8s event type based on severity.
func (eb *EventBuilder) eventType(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return corev1.EventTypeWarning
	case types.SeverityWarning:
		return corev1.EventTypeWarning
	default:
		return corev1.EventTypeNormal
	}
}

// formatGVR returns a string representation of a GroupVersionResource.
func formatGVR(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return fmt.Sprintf("core/%s/%s", gvr.Version, gvr.Resource)
	}
	return fmt.Sprintf("%s/%s/%s", gvr.Group, gvr.Version, gvr.Resource)
}

// gvrToKind converts a GVR to an approximate Kind name.
func gvrToKind(gvr schema.GroupVersionResource) string {
	// Simple heuristic: singularize and capitalize
	resource := gvr.Resource
	if strings.HasSuffix(resource, "ies") {
		resource = strings.TrimSuffix(resource, "ies") + "y"
	} else if strings.HasSuffix(resource, "s") {
		resource = strings.TrimSuffix(resource, "s")
	}

	if len(resource) == 0 {
		return resource
	}
	return strings.ToUpper(resource[:1]) + resource[1:]
}

// toKebabCase converts a CamelCase string to kebab-case.
func toKebabCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('-')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// genericSummary returns a generic summary for a constraint type.
func genericSummary(ct types.ConstraintType) string {
	switch ct {
	case types.ConstraintTypeNetworkIngress:
		return "Inbound network traffic is restricted by a network policy"
	case types.ConstraintTypeNetworkEgress:
		return "Outbound network traffic is restricted by a network policy"
	case types.ConstraintTypeAdmission:
		return "An admission policy may reject your resources"
	case types.ConstraintTypeResourceLimit:
		return "Resource quotas or limits apply to this namespace"
	case types.ConstraintTypeMeshPolicy:
		return "Service mesh policies affect this workload"
	case types.ConstraintTypeMissing:
		return "A required companion resource may be missing"
	default:
		return "A policy constraint affects this workload"
	}
}

// guessUnit returns the unit for a resource name.
func guessUnit(resourceName string) string {
	switch {
	case resourceName == "cpu" || strings.HasSuffix(resourceName, ".cpu"):
		return "cores"
	case resourceName == "memory" || strings.HasSuffix(resourceName, ".memory"):
		return "bytes"
	case resourceName == "pods":
		return "count"
	case resourceName == "services":
		return "count"
	case strings.Contains(resourceName, "storage"):
		return "bytes"
	default:
		return "count"
	}
}
