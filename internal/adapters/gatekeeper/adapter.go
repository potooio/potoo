package gatekeeper

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

const (
	// GatekeeperConstraintGroup is the API group for Gatekeeper constraint CRDs.
	GatekeeperConstraintGroup = "constraints.gatekeeper.sh"

	// DefaultVersion is the default API version for Gatekeeper constraints.
	DefaultVersion = "v1beta1"
)

// Adapter parses OPA Gatekeeper constraint resources.
type Adapter struct{}

// New creates a new Gatekeeper adapter.
func New() *Adapter {
	return &Adapter{}
}

// Name returns the adapter identifier.
func (a *Adapter) Name() string {
	return "gatekeeper"
}

// Handles returns the GVRs this adapter can parse.
// We use a wildcard resource to match all constraint types dynamically created
// from ConstraintTemplates.
func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Group:    GatekeeperConstraintGroup,
			Version:  DefaultVersion,
			Resource: "*", // Wildcard - matches any resource in this group
		},
	}
}

// Parse converts a Gatekeeper constraint into normalized Constraints.
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	kind := obj.GetKind()

	// Get spec
	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		return nil, fmt.Errorf("gatekeeper constraint %s: missing spec", name)
	}

	// Parse enforcement action → severity
	enforcementAction := util.SafeNestedString(spec, "enforcementAction")
	if enforcementAction == "" {
		enforcementAction = "deny" // Default in Gatekeeper
	}
	severity := mapEnforcementToSeverity(enforcementAction)
	effect := mapEnforcementToEffect(enforcementAction)

	// Parse match block
	match := util.SafeNestedMap(spec, "match")
	affectedNamespaces, excludedNamespaces := extractNamespaces(match)
	resourceTargets := extractResourceTargets(match)
	workloadSelector := extractLabelSelector(match)
	namespaceSelector := extractNamespaceSelector(match)

	// Build summary
	summary := buildSummary(kind, name, enforcementAction, resourceTargets, affectedNamespaces)

	// Extract parameters for details
	parameters := util.SafeNestedMap(spec, "parameters")
	details := buildDetails(enforcementAction, resourceTargets, affectedNamespaces, excludedNamespaces, parameters)

	// Build tags
	tags := buildTags(kind, enforcementAction)

	// Build remediation steps
	remediation := buildRemediation(kind, name)

	constraint := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvrFromObject(obj),
		Name:               name,
		Namespace:          "", // Gatekeeper constraints are cluster-scoped
		AffectedNamespaces: affectedNamespaces,
		NamespaceSelector:  namespaceSelector,
		WorkloadSelector:   workloadSelector,
		ResourceTargets:    resourceTargets,
		ConstraintType:     types.ConstraintTypeAdmission,
		Effect:             effect,
		Severity:           severity,
		Summary:            summary,
		RemediationHint:    fmt.Sprintf("Review Gatekeeper constraint %s/%s or contact your platform team", kind, name),
		Remediation:        remediation,
		Details:            details,
		Tags:               tags,
		RawObject:          obj.DeepCopy(),
	}

	return []types.Constraint{constraint}, nil
}

// gvrFromObject extracts the GVR from an unstructured object.
func gvrFromObject(obj *unstructured.Unstructured) schema.GroupVersionResource {
	gvk := obj.GroupVersionKind()
	return schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: strings.ToLower(gvk.Kind) + "s", // Approximate pluralization
	}
}

// mapEnforcementToSeverity maps Gatekeeper enforcement action to severity.
func mapEnforcementToSeverity(action string) types.Severity {
	switch strings.ToLower(action) {
	case "deny":
		return types.SeverityCritical
	case "warn":
		return types.SeverityWarning
	case "dryrun":
		return types.SeverityInfo
	default:
		return types.SeverityCritical // Unknown defaults to deny behavior
	}
}

// mapEnforcementToEffect maps Gatekeeper enforcement action to effect.
func mapEnforcementToEffect(action string) string {
	switch strings.ToLower(action) {
	case "deny":
		return "deny"
	case "warn":
		return "warn"
	case "dryrun":
		return "audit"
	default:
		return "deny"
	}
}

// extractNamespaces extracts affected and excluded namespaces from match block.
func extractNamespaces(match map[string]interface{}) (affected, excluded []string) {
	if match == nil {
		return nil, nil
	}
	affected = util.SafeNestedStringSlice(match, "namespaces")
	excluded = util.SafeNestedStringSlice(match, "excludedNamespaces")
	return
}

// extractResourceTargets extracts the resource kinds being constrained.
func extractResourceTargets(match map[string]interface{}) []types.ResourceTarget {
	if match == nil {
		return nil
	}

	kindsSlice := util.SafeNestedSlice(match, "kinds")
	if kindsSlice == nil {
		return nil
	}

	var targets []types.ResourceTarget
	for _, k := range kindsSlice {
		kindMap, ok := k.(map[string]interface{})
		if !ok {
			continue
		}

		apiGroups := util.SafeNestedStringSlice(kindMap, "apiGroups")
		kinds := util.SafeNestedStringSlice(kindMap, "kinds")

		if len(kinds) > 0 {
			// Convert kinds to resources (lowercase plural)
			resources := make([]string, len(kinds))
			for i, kind := range kinds {
				resources[i] = strings.ToLower(kind) + "s"
			}
			targets = append(targets, types.ResourceTarget{
				APIGroups: apiGroups,
				Resources: resources,
			})
		}
	}

	return targets
}

// extractLabelSelector extracts the workload label selector from match block.
func extractLabelSelector(match map[string]interface{}) *metav1.LabelSelector {
	if match == nil {
		return nil
	}
	return util.SafeNestedLabelSelector(match, "labelSelector")
}

// extractNamespaceSelector extracts the namespace selector from match block.
func extractNamespaceSelector(match map[string]interface{}) *metav1.LabelSelector {
	if match == nil {
		return nil
	}
	return util.SafeNestedLabelSelector(match, "namespaceSelector")
}

// buildSummary creates a human-readable summary.
func buildSummary(kind, name, enforcementAction string, targets []types.ResourceTarget, namespaces []string) string {
	actionVerb := "validates"
	switch strings.ToLower(enforcementAction) {
	case "deny":
		actionVerb = "rejects"
	case "warn":
		actionVerb = "warns on"
	case "dryrun":
		actionVerb = "audits"
	}

	// Build resource list
	resourceList := "resources"
	if len(targets) > 0 {
		var kinds []string
		for _, t := range targets {
			kinds = append(kinds, t.Resources...)
		}
		if len(kinds) > 0 {
			if len(kinds) <= 3 {
				resourceList = strings.Join(kinds, ", ")
			} else {
				resourceList = fmt.Sprintf("%d resource types", len(kinds))
			}
		}
	}

	// Build namespace scope
	nsScope := ""
	if len(namespaces) > 0 {
		if len(namespaces) <= 2 {
			nsScope = fmt.Sprintf(" in %s", strings.Join(namespaces, ", "))
		} else {
			nsScope = fmt.Sprintf(" in %d namespaces", len(namespaces))
		}
	}

	return fmt.Sprintf("Gatekeeper %s %q %s %s%s", kind, name, actionVerb, resourceList, nsScope)
}

// buildDetails creates the details map.
func buildDetails(enforcementAction string, targets []types.ResourceTarget, affected, excluded []string, parameters map[string]interface{}) map[string]interface{} {
	details := map[string]interface{}{
		"enforcementAction": enforcementAction,
	}

	if len(targets) > 0 {
		details["resourceTargets"] = targets
	}
	if len(affected) > 0 {
		details["affectedNamespaces"] = affected
	}
	if len(excluded) > 0 {
		details["excludedNamespaces"] = excluded
	}
	if len(parameters) > 0 {
		details["parameters"] = parameters
	}

	return details
}

// buildTags creates tags for filtering.
func buildTags(kind, enforcementAction string) []string {
	tags := []string{
		"gatekeeper",
		"admission",
		"opa",
		strings.ToLower(kind),
	}

	switch strings.ToLower(enforcementAction) {
	case "deny":
		tags = append(tags, "blocking")
	case "warn":
		tags = append(tags, "warning")
	case "dryrun":
		tags = append(tags, "audit")
	}

	return tags
}

// buildRemediation creates remediation steps.
func buildRemediation(kind, name string) []types.RemediationStep {
	return []types.RemediationStep{
		{
			Type:              "kubectl",
			Description:       "View the constraint details",
			Command:           fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(kind), name),
			RequiresPrivilege: "developer",
		},
		{
			Type:              "kubectl",
			Description:       "Check for violations",
			Command:           fmt.Sprintf("kubectl get %s %s -o jsonpath='{.status.totalViolations}'", strings.ToLower(kind), name),
			RequiresPrivilege: "developer",
		},
		{
			Type:              "manual",
			Description:       "Contact platform team to request an exception or policy modification",
			Contact:           "platform-team@company.com",
			RequiresPrivilege: "developer",
		},
		{
			Type:              "link",
			Description:       "Gatekeeper documentation",
			URL:               "https://open-policy-agent.github.io/gatekeeper/website/docs/",
			RequiresPrivilege: "developer",
		},
	}
}
