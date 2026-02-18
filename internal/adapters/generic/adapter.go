package generic

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

// ParseConfig provides optional overrides for generic adapter parsing.
// The discovery engine populates this from ConstraintProfile resources.
type ParseConfig struct {
	FieldPaths       *v1alpha1.FieldPaths
	SeverityOverride string
}

const (
	annotationSummary  = "potoo.io/summary"
	annotationSeverity = "potoo.io/severity"
	annotationType     = "potoo.io/constraint-type"
)

// Adapter is a fallback adapter for unknown CRDs.
// Unlike other adapters, it does not register specific GVRs.
// The discovery engine calls it directly when no specific adapter matches.
type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "generic"
}

// Handles returns an empty slice because the generic adapter is used as a fallback,
// not registered to specific GVRs.
func (a *Adapter) Handles() []schema.GroupVersionResource {
	return nil
}

// ParseWithGVR parses an unknown CRD and returns a single constraint.
// This is the main entry point for the generic adapter - it requires the GVR
// to be passed explicitly since it's not registered in the registry.
func (a *Adapter) ParseWithGVR(ctx context.Context, obj *unstructured.Unstructured, gvr schema.GroupVersionResource) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	kind := obj.GetKind()
	annotations := obj.GetAnnotations()

	// Extract summary from annotation or generate default
	summary := getAnnotation(annotations, annotationSummary)
	if summary == "" {
		if namespace != "" {
			summary = fmt.Sprintf("%s %q in namespace %q", kind, name, namespace)
		} else {
			summary = fmt.Sprintf("%s %q (cluster-scoped)", kind, name)
		}
	}

	// Extract severity from annotation or default to Info
	severity := types.SeverityInfo
	if severityStr := getAnnotation(annotations, annotationSeverity); severityStr != "" {
		switch severityStr {
		case "Critical", "critical":
			severity = types.SeverityCritical
		case "Warning", "warning":
			severity = types.SeverityWarning
		case "Info", "info":
			severity = types.SeverityInfo
		}
	}

	// Extract constraint type from annotation or default to Unknown
	constraintType := types.ConstraintTypeUnknown
	if typeStr := getAnnotation(annotations, annotationType); typeStr != "" {
		switch typeStr {
		case "NetworkIngress":
			constraintType = types.ConstraintTypeNetworkIngress
		case "NetworkEgress":
			constraintType = types.ConstraintTypeNetworkEgress
		case "Admission":
			constraintType = types.ConstraintTypeAdmission
		case "ResourceLimit":
			constraintType = types.ConstraintTypeResourceLimit
		case "MeshPolicy":
			constraintType = types.ConstraintTypeMeshPolicy
		case "MissingResource":
			constraintType = types.ConstraintTypeMissing
		}
	}

	// Build details by extracting common fields
	details := map[string]interface{}{}
	discoveredFields := []string{}

	spec := util.SafeNestedMap(obj.Object, "spec")

	// Look for common selectors
	var workloadSelector, namespaceSelector = extractSelectors(spec)
	if workloadSelector != nil {
		discoveredFields = append(discoveredFields, "workloadSelector")
	}
	if namespaceSelector != nil {
		discoveredFields = append(discoveredFields, "namespaceSelector")
	}

	// Look for common policy patterns
	if rules := util.SafeNestedSlice(spec, "rules"); len(rules) > 0 {
		details["ruleCount"] = len(rules)
		discoveredFields = append(discoveredFields, "rules")
	}

	if params := util.SafeNestedMap(spec, "parameters"); params != nil {
		details["hasParameters"] = true
		discoveredFields = append(discoveredFields, "parameters")
	}

	// Look for match block (common in Gatekeeper/Kyverno)
	if match := util.SafeNestedMap(spec, "match"); match != nil {
		if kinds := util.SafeNestedSlice(match, "kinds"); len(kinds) > 0 {
			details["matchKinds"] = len(kinds)
			discoveredFields = append(discoveredFields, "match.kinds")
		}
		if ns := util.SafeNestedStringSlice(match, "namespaces"); len(ns) > 0 {
			details["matchNamespaces"] = ns
			discoveredFields = append(discoveredFields, "match.namespaces")
		}
	}

	// Store what we found
	if len(discoveredFields) > 0 {
		details["discoveredFields"] = discoveredFields
	}

	// Determine affected namespaces
	var affectedNamespaces []string
	if namespace != "" {
		affectedNamespaces = []string{namespace}
	}

	c := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvr,
		Name:               name,
		Namespace:          namespace,
		AffectedNamespaces: affectedNamespaces,
		WorkloadSelector:   workloadSelector,
		NamespaceSelector:  namespaceSelector,
		ConstraintType:     constraintType,
		Effect:             "unknown",
		Severity:           severity,
		Summary:            summary,
		RemediationHint:    "This constraint was auto-discovered. Contact your platform team for details.",
		Details:            details,
		RawObject:          obj.DeepCopy(),
	}

	return []types.Constraint{c}, nil
}

// ParseWithConfig parses a CRD using optional field-path configuration from a
// ConstraintProfile. When cfg.FieldPaths is non-nil, the configured paths are
// used instead of the default hardcoded selector probing.
func (a *Adapter) ParseWithConfig(ctx context.Context, obj *unstructured.Unstructured, gvr schema.GroupVersionResource, cfg ParseConfig) ([]types.Constraint, error) {
	constraints, err := a.ParseWithGVR(ctx, obj, gvr)
	if err != nil {
		return nil, err
	}
	if len(constraints) == 0 {
		return constraints, nil
	}

	c := &constraints[0]

	// Apply severity override from ConstraintProfile, but only when
	// no per-object annotation is present (annotation takes highest precedence).
	if cfg.SeverityOverride != "" && getAnnotation(obj.GetAnnotations(), annotationSeverity) == "" {
		switch cfg.SeverityOverride {
		case "Critical":
			c.Severity = types.SeverityCritical
		case "Warning":
			c.Severity = types.SeverityWarning
		case "Info":
			c.Severity = types.SeverityInfo
		}
	}

	if cfg.FieldPaths == nil {
		return constraints, nil
	}

	// Re-extract selectors using configured paths
	if cfg.FieldPaths.SelectorPath != "" {
		fields := splitFieldPath(cfg.FieldPaths.SelectorPath)
		if sel := util.SafeNestedLabelSelector(obj.Object, fields...); sel != nil {
			c.WorkloadSelector = sel
		}
	}
	if cfg.FieldPaths.NamespaceSelectorPath != "" {
		fields := splitFieldPath(cfg.FieldPaths.NamespaceSelectorPath)
		if sel := util.SafeNestedLabelSelector(obj.Object, fields...); sel != nil {
			c.NamespaceSelector = sel
		}
	}

	// Extract effect from configured path
	if cfg.FieldPaths.EffectPath != "" {
		fields := splitFieldPath(cfg.FieldPaths.EffectPath)
		if effect := util.SafeNestedString(obj.Object, fields...); effect != "" {
			c.Effect = effect
		}
	}

	// Extract summary from configured path (annotation still takes precedence)
	if cfg.FieldPaths.SummaryPath != "" && getAnnotation(obj.GetAnnotations(), annotationSummary) == "" {
		fields := splitFieldPath(cfg.FieldPaths.SummaryPath)
		if summary := util.SafeNestedString(obj.Object, fields...); summary != "" {
			c.Summary = summary
		}
	}

	return constraints, nil
}

// Parse implements the Adapter interface but requires GVR context.
// Use ParseWithGVR for direct calls.
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	// Extract GVR from the object's GVK
	gvk := obj.GroupVersionKind()
	gvr := schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: guessResource(gvk.Kind),
	}
	return a.ParseWithGVR(ctx, obj, gvr)
}

// extractSelectors looks for common selector patterns in the spec.
func extractSelectors(spec map[string]interface{}) (workload, namespace *metav1.LabelSelector) {
	if spec == nil {
		return nil, nil
	}

	// Try various common selector field names
	workload = util.SafeNestedLabelSelector(spec, "selector")
	if workload == nil {
		workload = util.SafeNestedLabelSelector(spec, "podSelector")
	}
	if workload == nil {
		workload = util.SafeNestedLabelSelector(spec, "workloadSelector")
	}

	namespace = util.SafeNestedLabelSelector(spec, "namespaceSelector")

	return workload, namespace
}

// getAnnotation safely retrieves an annotation value.
func getAnnotation(annotations map[string]string, key string) string {
	if annotations == nil {
		return ""
	}
	return annotations[key]
}

// guessResource guesses the resource name from a Kind.
// This is a simple pluralization heuristic.
func guessResource(kind string) string {
	if kind == "" {
		return "unknown"
	}
	// Simple pluralization - good enough for most cases
	lower := strings.ToLower(kind)
	if strings.HasSuffix(lower, "y") {
		return lower[:len(lower)-1] + "ies"
	}
	if strings.HasSuffix(lower, "s") || strings.HasSuffix(lower, "x") ||
		strings.HasSuffix(lower, "ch") || strings.HasSuffix(lower, "sh") {
		return lower + "es"
	}
	return lower + "s"
}

// splitFieldPath splits a dot-delimited field path into components.
// Returns nil for empty paths. Filters out empty segments from leading/trailing dots.
func splitFieldPath(path string) []string {
	if path == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(path, ".") {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
