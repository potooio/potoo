package resourcequota

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var gvr = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "resourcequotas",
}

// Adapter parses core/v1 ResourceQuota resources.
type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "resourcequota"
}

func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvr}
}

func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		return nil, fmt.Errorf("resourcequota %s/%s: missing spec", namespace, name)
	}

	// Get hard limits from spec
	hard := util.SafeNestedMap(spec, "hard")
	if len(hard) == 0 {
		return nil, nil // No limits defined
	}

	// Get used values from status (may be nil for new quotas)
	status := util.SafeNestedMap(obj.Object, "status")
	used := util.SafeNestedMap(status, "used")

	// Compute usage percentages for each resource
	resources := make(map[string]map[string]interface{})
	var maxPercent float64

	// Sort resource names for deterministic ordering
	var resourceNames []string
	for k := range hard {
		resourceNames = append(resourceNames, k)
	}
	sort.Strings(resourceNames)

	for _, resourceName := range resourceNames {
		hardVal := hard[resourceName]
		hardStr, ok := hardVal.(string)
		if !ok {
			continue
		}

		hardQty, err := resource.ParseQuantity(hardStr)
		if err != nil {
			continue
		}

		resourceInfo := map[string]interface{}{
			"hard": hardStr,
		}

		if used != nil {
			if usedVal, exists := used[resourceName]; exists {
				usedStr, ok := usedVal.(string)
				if ok {
					usedQty, err := resource.ParseQuantity(usedStr)
					if err == nil {
						resourceInfo["used"] = usedStr

						// Calculate percentage
						if !hardQty.IsZero() {
							// Use millivalue for CPU or value for others
							var percent float64
							if isCPUResource(resourceName) {
								percent = float64(usedQty.MilliValue()) / float64(hardQty.MilliValue()) * 100
							} else if isMemoryResource(resourceName) {
								percent = float64(usedQty.Value()) / float64(hardQty.Value()) * 100
							} else {
								// For counts like pods, use Value()
								percent = float64(usedQty.Value()) / float64(hardQty.Value()) * 100
							}
							resourceInfo["percent"] = int(percent)
							if percent > maxPercent {
								maxPercent = percent
							}
						}
					}
				}
			}
		}

		resources[resourceName] = resourceInfo
	}

	// Determine severity based on highest usage percentage
	severity := types.SeverityInfo
	if maxPercent >= 90 {
		severity = types.SeverityCritical
	} else if maxPercent >= 75 {
		severity = types.SeverityWarning
	}

	c := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvr,
		Name:               name,
		Namespace:          namespace,
		AffectedNamespaces: []string{namespace},
		ConstraintType:     types.ConstraintTypeResourceLimit,
		Effect:             "limit",
		Severity:           severity,
		Summary:            buildSummary(resources),
		RemediationHint:    "Request quota increase or reduce resource usage",
		Details:            map[string]interface{}{"resources": resources},
		RawObject:          obj.DeepCopy(),
	}

	return []types.Constraint{c}, nil
}

// buildSummary creates a human-readable summary of resource usage.
func buildSummary(resources map[string]map[string]interface{}) string {
	var parts []string

	// Sort for deterministic order
	var names []string
	for name := range resources {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		info := resources[name]
		hard := info["hard"]

		var part string
		if usedVal, ok := info["used"]; ok {
			if percentVal, ok := info["percent"]; ok {
				part = fmt.Sprintf("%s: %v/%v (%v%%)", formatResourceName(name), usedVal, hard, percentVal)
			} else {
				part = fmt.Sprintf("%s: %v/%v", formatResourceName(name), usedVal, hard)
			}
		} else {
			part = fmt.Sprintf("%s: limit %v", formatResourceName(name), hard)
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, "; ")
}

// formatResourceName returns a display-friendly resource name.
func formatResourceName(name string) string {
	switch name {
	case "cpu":
		return "CPU"
	case "memory":
		return "Memory"
	case "pods":
		return "Pods"
	case "services":
		return "Services"
	case "secrets":
		return "Secrets"
	case "configmaps":
		return "ConfigMaps"
	case "persistentvolumeclaims":
		return "PVCs"
	default:
		return name
	}
}

// isCPUResource returns true if the resource name is a CPU resource.
func isCPUResource(name string) bool {
	return name == "cpu" || strings.HasSuffix(name, ".cpu")
}

// isMemoryResource returns true if the resource name is a memory resource.
func isMemoryResource(name string) bool {
	return name == "memory" || strings.HasSuffix(name, ".memory")
}
