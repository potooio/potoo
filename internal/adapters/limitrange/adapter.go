package limitrange

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var gvr = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "limitranges",
}

// Adapter parses core/v1 LimitRange resources.
type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "limitrange"
}

func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvr}
}

func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		return nil, fmt.Errorf("limitrange %s/%s: missing spec", namespace, name)
	}

	limits := util.SafeNestedSlice(spec, "limits")
	if len(limits) == 0 {
		return nil, nil // No limits defined
	}

	var constraints []types.Constraint

	for i, limitRaw := range limits {
		limitMap, ok := limitRaw.(map[string]interface{})
		if !ok {
			continue
		}

		limitType := util.SafeStringFromMap(limitMap, "type")
		if limitType == "" {
			limitType = "Container" // default type
		}

		details := map[string]interface{}{
			"type": limitType,
		}

		// Extract all limit fields
		if defaultVals := extractResourceMap(limitMap, "default"); len(defaultVals) > 0 {
			details["default"] = defaultVals
		}
		if defaultRequestVals := extractResourceMap(limitMap, "defaultRequest"); len(defaultRequestVals) > 0 {
			details["defaultRequest"] = defaultRequestVals
		}
		if maxVals := extractResourceMap(limitMap, "max"); len(maxVals) > 0 {
			details["max"] = maxVals
		}
		if minVals := extractResourceMap(limitMap, "min"); len(minVals) > 0 {
			details["min"] = minVals
		}
		if ratioVals := extractResourceMap(limitMap, "maxLimitRequestRatio"); len(ratioVals) > 0 {
			details["maxLimitRequestRatio"] = ratioVals
		}

		// Create unique UID by appending index to parent UID
		uid := k8stypes.UID(fmt.Sprintf("%s-%d", obj.GetUID(), i))

		c := types.Constraint{
			UID:                uid,
			Source:             gvr,
			Name:               fmt.Sprintf("%s-%s-%d", name, strings.ToLower(limitType), i),
			Namespace:          namespace,
			AffectedNamespaces: []string{namespace},
			ConstraintType:     types.ConstraintTypeResourceLimit,
			Effect:             "limit",
			Severity:           types.SeverityInfo,
			Summary:            buildLimitSummary(limitType, details),
			RemediationHint:    fmt.Sprintf("Ensure your %ss specify resource requests/limits within these bounds", strings.ToLower(limitType)),
			Details:            details,
			RawObject:          obj.DeepCopy(),
		}

		constraints = append(constraints, c)
	}

	return constraints, nil
}

// extractResourceMap extracts a map of resource quantities from the limit entry.
func extractResourceMap(limitMap map[string]interface{}, field string) map[string]string {
	result := make(map[string]string)
	resourceMap := util.SafeNestedMap(limitMap, field)
	if resourceMap == nil {
		return result
	}
	for k, v := range resourceMap {
		if strVal, ok := v.(string); ok {
			result[k] = strVal
		}
	}
	return result
}

// buildLimitSummary creates a human-readable summary for a limit entry.
func buildLimitSummary(limitType string, details map[string]interface{}) string {
	var parts []string

	// Add min-max range if both present
	minVals, hasMin := details["min"].(map[string]string)
	maxVals, hasMax := details["max"].(map[string]string)

	if hasMin || hasMax {
		var resourceRanges []string

		// Collect all resources mentioned in min or max
		allResources := make(map[string]bool)
		if hasMin {
			for k := range minVals {
				allResources[k] = true
			}
		}
		if hasMax {
			for k := range maxVals {
				allResources[k] = true
			}
		}

		// Sort for deterministic order
		var sortedResources []string
		for r := range allResources {
			sortedResources = append(sortedResources, r)
		}
		sort.Strings(sortedResources)

		for _, resource := range sortedResources {
			var minStr, maxStr string
			if hasMin {
				minStr = minVals[resource]
			}
			if hasMax {
				maxStr = maxVals[resource]
			}

			resourceName := formatResourceName(resource)
			if minStr != "" && maxStr != "" {
				resourceRanges = append(resourceRanges, fmt.Sprintf("%s %s-%s", resourceName, minStr, maxStr))
			} else if maxStr != "" {
				resourceRanges = append(resourceRanges, fmt.Sprintf("%s max %s", resourceName, maxStr))
			} else if minStr != "" {
				resourceRanges = append(resourceRanges, fmt.Sprintf("%s min %s", resourceName, minStr))
			}
		}

		if len(resourceRanges) > 0 {
			parts = append(parts, strings.Join(resourceRanges, ", "))
		}
	}

	// Add default values if present
	if defaultVals, ok := details["default"].(map[string]string); ok && len(defaultVals) > 0 {
		var defaultParts []string
		var sortedResources []string
		for r := range defaultVals {
			sortedResources = append(sortedResources, r)
		}
		sort.Strings(sortedResources)
		for _, r := range sortedResources {
			defaultParts = append(defaultParts, fmt.Sprintf("%s=%s", formatResourceName(r), defaultVals[r]))
		}
		parts = append(parts, fmt.Sprintf("defaults: %s", strings.Join(defaultParts, ", ")))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%s limits defined", limitType)
	}

	return fmt.Sprintf("%s limits: %s", limitType, strings.Join(parts, "; "))
}

// formatResourceName returns a display-friendly resource name.
func formatResourceName(name string) string {
	switch name {
	case "cpu":
		return "CPU"
	case "memory":
		return "Memory"
	default:
		return name
	}
}
