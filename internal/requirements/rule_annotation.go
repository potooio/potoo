package requirements

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/potooio/potoo/internal/annotations"
	"github.com/potooio/potoo/internal/types"
)

// requirementEntry is a single entry in the potoo.io/requires annotation.
type requirementEntry struct {
	GVR      string `json:"gvr"`
	Matching string `json:"matching,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type annotationRule struct{}

// NewAnnotationRule returns a rule that checks for companion resources declared
// in the potoo.io/requires workload annotation.
func NewAnnotationRule() types.RequirementRule {
	return &annotationRule{}
}

func (r *annotationRule) Name() string { return "annotation-requirements" }

func (r *annotationRule) Description() string {
	return "Checks for companion resources declared in the potoo.io/requires annotation"
}

func (r *annotationRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	ann := workload.GetAnnotations()
	if ann == nil {
		return nil, nil
	}
	raw, ok := ann[annotations.WorkloadRequires]
	if !ok || raw == "" {
		return nil, nil
	}

	namespace := workload.GetNamespace()
	if namespace == "" {
		return nil, nil
	}

	var entries []requirementEntry
	if err := yaml.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("parse %s annotation: %w", annotations.WorkloadRequires, err)
	}

	workloadName := workload.GetName()
	var result []types.Constraint

	for i, entry := range entries {
		gvr, err := parseGVR(entry.GVR)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}

		matchLabels, err := parseMatchingLabels(entry.Matching)
		if err != nil {
			return nil, fmt.Errorf("entry %d: invalid matching %q: %w", i, entry.Matching, err)
		}

		resources, err := eval.ListByGVR(ctx, gvr, namespace)
		if err != nil {
			return nil, err
		}

		if hasMatchingResource(resources, matchLabels) {
			continue
		}

		reason := entry.Reason
		if reason == "" {
			reason = fmt.Sprintf("Required resource %s/%s/%s not found", gvr.Group, gvr.Version, gvr.Resource)
		}

		result = append(result, types.Constraint{
			UID:                k8stypes.UID(fmt.Sprintf("missing:annotation:%s/%s:%s/%s/%s", namespace, workloadName, gvr.Group, gvr.Version, gvr.Resource)),
			Name:               fmt.Sprintf("missing-%s-%s", gvr.Resource, workloadName),
			Namespace:          namespace,
			AffectedNamespaces: []string{namespace},
			ConstraintType:     types.ConstraintTypeMissing,
			Effect:             "missing",
			Severity:           types.SeverityWarning,
			Summary:            reason,
			Details: map[string]interface{}{
				"expectedGVR": fmt.Sprintf("%s/%s/%s", gvr.Group, gvr.Version, gvr.Resource),
				"reason":      reason,
			},
			Tags: []string{"annotation-requirements", "missing-resource"},
		})
	}

	return result, nil
}

// parseGVR parses a GVR string in the format "group/version/resource".
// Core API resources may omit the group: "v1/services" is equivalent to "/v1/services".
func parseGVR(s string) (schema.GroupVersionResource, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return schema.GroupVersionResource{}, fmt.Errorf("empty GVR")
	}

	parts := strings.SplitN(s, "/", 3)
	var gvr schema.GroupVersionResource
	switch len(parts) {
	case 3:
		gvr = schema.GroupVersionResource{
			Group: parts[0], Version: parts[1], Resource: parts[2],
		}
	case 2:
		// Core API: "v1/services" → Group="", Version="v1", Resource="services"
		gvr = schema.GroupVersionResource{
			Group: "", Version: parts[0], Resource: parts[1],
		}
	default:
		return schema.GroupVersionResource{}, fmt.Errorf("invalid GVR format %q: expected group/version/resource", s)
	}

	if strings.Contains(gvr.Resource, "/") {
		return schema.GroupVersionResource{}, fmt.Errorf("invalid GVR format %q: resource name must not contain slashes", s)
	}
	if gvr.Version == "" || gvr.Resource == "" {
		return schema.GroupVersionResource{}, fmt.Errorf("invalid GVR format %q: version and resource are required", s)
	}
	return gvr, nil
}

// parseMatchingLabels parses a label selector string (e.g. "app=my-service,tier=backend")
// into a label map. Returns nil map for empty input.
func parseMatchingLabels(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	sel, err := labels.ConvertSelectorToLabelsMap(s)
	if err != nil {
		return nil, err
	}
	return map[string]string(sel), nil
}

// hasMatchingResource returns true if any resource in the list has labels matching
// all of the specified matchLabels. If matchLabels is nil, any resource matches.
func hasMatchingResource(resources []*unstructured.Unstructured, matchLabels map[string]string) bool {
	if len(resources) == 0 {
		return false
	}
	if len(matchLabels) == 0 {
		return true
	}
	for _, obj := range resources {
		objLabels := obj.GetLabels()
		if labelsMatch(objLabels, matchLabels) {
			return true
		}
	}
	return false
}

// labelsMatch returns true if all required labels are present with matching values.
func labelsMatch(objLabels, required map[string]string) bool {
	for k, v := range required {
		if objLabels[k] != v {
			return false
		}
	}
	return true
}
