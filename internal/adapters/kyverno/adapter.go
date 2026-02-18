package kyverno

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

// sharedRawObject is used to avoid deep-copying the policy object for each rule.
// The first rule gets the deep copy, subsequent rules share a reference.
type sharedRawObject struct {
	obj *unstructured.Unstructured
}

var (
	gvrClusterPolicy = schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "clusterpolicies",
	}
	gvrPolicy = schema.GroupVersionResource{
		Group:    "kyverno.io",
		Version:  "v1",
		Resource: "policies",
	}
)

// Adapter parses Kyverno policies.
type Adapter struct{}

// New creates a new Kyverno adapter.
func New() *Adapter {
	return &Adapter{}
}

// Name returns the adapter identifier.
func (a *Adapter) Name() string {
	return "kyverno"
}

// Handles returns the GVRs this adapter can parse.
func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvrClusterPolicy, gvrPolicy}
}

// Parse converts a Kyverno policy into normalized Constraints.
// Each rule in the policy becomes a separate Constraint.
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	kind := obj.GetKind()
	isClusterPolicy := kind == "ClusterPolicy"

	// Get spec
	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		return nil, fmt.Errorf("kyverno policy %s: missing spec", name)
	}

	// Get global validation failure action
	globalAction := util.SafeNestedString(spec, "validationFailureAction")
	if globalAction == "" {
		globalAction = "Audit" // Default in Kyverno
	}

	// Parse rules
	rulesSlice := util.SafeNestedSlice(spec, "rules")
	if len(rulesSlice) == 0 {
		return nil, fmt.Errorf("kyverno policy %s: no rules defined", name)
	}

	// Create a single deep copy to share across all rules (memory optimization)
	shared := &sharedRawObject{obj: obj.DeepCopy()}

	var constraints []types.Constraint

	for i, ruleRaw := range rulesSlice {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		c, err := a.parseRule(obj, rule, i, globalAction, isClusterPolicy, shared)
		if err != nil {
			// Log but continue parsing other rules
			continue
		}
		if c != nil {
			constraints = append(constraints, *c)
		}
	}

	if len(constraints) == 0 {
		return nil, fmt.Errorf("kyverno policy %s: no valid rules parsed", name)
	}

	return constraints, nil
}

// parseRule parses a single Kyverno rule into a Constraint.
func (a *Adapter) parseRule(obj *unstructured.Unstructured, rule map[string]interface{}, index int, globalAction string, isClusterPolicy bool, shared *sharedRawObject) (*types.Constraint, error) {
	policyName := obj.GetName()
	namespace := obj.GetNamespace()

	ruleName := util.SafeStringFromMap(rule, "name")
	if ruleName == "" {
		ruleName = fmt.Sprintf("rule-%d", index)
	}

	// Determine rule type and effect
	ruleType, effect := determineRuleType(rule)

	// Determine severity based on rule type and validation action
	var severity types.Severity
	var action string

	if ruleType == "validate" {
		// Check for rule-level validationFailureAction override
		action = util.SafeNestedString(rule, "validate", "validationFailureAction")
		if action == "" {
			action = globalAction
		}
		severity = mapValidationActionToSeverity(action)
	} else {
		// Non-validation rules are informational
		severity = types.SeverityInfo
		action = "mutate"
	}

	// Parse match block
	match := util.SafeNestedMap(rule, "match")
	affectedNamespaces, resourceTargets, workloadSelector := extractMatchInfo(match)

	// For namespace-scoped policies, add the policy's namespace
	if !isClusterPolicy && namespace != "" {
		if len(affectedNamespaces) == 0 {
			affectedNamespaces = []string{namespace}
		}
	}

	// Build summary
	summary := buildRuleSummary(policyName, ruleName, ruleType, action, resourceTargets, isClusterPolicy)

	// Build details
	details := buildRuleDetails(rule, ruleType, action, resourceTargets)

	// Build tags
	tags := buildTags(ruleType, action, isClusterPolicy)

	// Build remediation
	remediation := buildRemediation(policyName, namespace, isClusterPolicy)

	// Generate unique UID per rule
	ruleUID := ktypes.UID(fmt.Sprintf("%s-rule-%d", obj.GetUID(), index))

	// Determine source GVR
	source := gvrPolicy
	if isClusterPolicy {
		source = gvrClusterPolicy
	}

	return &types.Constraint{
		UID:                ruleUID,
		Source:             source,
		Name:               fmt.Sprintf("%s/%s", policyName, ruleName),
		Namespace:          namespace,
		AffectedNamespaces: affectedNamespaces,
		WorkloadSelector:   workloadSelector,
		ResourceTargets:    resourceTargets,
		ConstraintType:     mapRuleTypeToConstraintType(ruleType),
		Effect:             effect,
		Severity:           severity,
		Summary:            summary,
		RemediationHint:    fmt.Sprintf("Review Kyverno policy %s or contact your platform team", policyName),
		Remediation:        remediation,
		Details:            details,
		Tags:               tags,
		RawObject:          shared.obj, // Share the deep copy across all rules
	}, nil
}

// determineRuleType determines the type and effect of a Kyverno rule.
func determineRuleType(rule map[string]interface{}) (ruleType, effect string) {
	if util.SafeNestedMap(rule, "validate") != nil {
		return "validate", "deny"
	}
	if util.SafeNestedMap(rule, "mutate") != nil {
		return "mutate", "mutate"
	}
	if util.SafeNestedMap(rule, "generate") != nil {
		return "generate", "generate"
	}
	if util.SafeNestedMap(rule, "verifyImages") != nil || util.SafeNestedSlice(rule, "verifyImages") != nil {
		return "verifyImages", "deny"
	}
	return "unknown", "unknown"
}

// mapValidationActionToSeverity maps Kyverno validation action to severity.
func mapValidationActionToSeverity(action string) types.Severity {
	switch strings.ToLower(action) {
	case "enforce":
		return types.SeverityCritical
	case "audit":
		return types.SeverityWarning
	default:
		return types.SeverityWarning
	}
}

// mapRuleTypeToConstraintType maps Kyverno rule type to constraint type.
func mapRuleTypeToConstraintType(ruleType string) types.ConstraintType {
	switch ruleType {
	case "validate", "verifyImages":
		return types.ConstraintTypeAdmission
	case "mutate", "generate":
		return types.ConstraintTypeAdmission
	default:
		return types.ConstraintTypeUnknown
	}
}

// extractMatchInfo extracts namespace, resource targets, and selector from match block.
func extractMatchInfo(match map[string]interface{}) (namespaces []string, targets []types.ResourceTarget, selector *metav1.LabelSelector) {
	if match == nil {
		return nil, nil, nil
	}

	// Kyverno can have match.any or match.all
	anySlice := util.SafeNestedSlice(match, "any")
	allSlice := util.SafeNestedSlice(match, "all")

	// Also support legacy direct resources field
	if resources := util.SafeNestedMap(match, "resources"); resources != nil {
		ns, tgt, sel := extractFromResources(resources)
		namespaces = append(namespaces, ns...)
		targets = append(targets, tgt...)
		if sel != nil {
			selector = sel
		}
	}

	// Process any clauses
	for _, clause := range anySlice {
		clauseMap, ok := clause.(map[string]interface{})
		if !ok {
			continue
		}
		if resources := util.SafeNestedMap(clauseMap, "resources"); resources != nil {
			ns, tgt, sel := extractFromResources(resources)
			namespaces = append(namespaces, ns...)
			targets = append(targets, tgt...)
			if sel != nil && selector == nil {
				selector = sel
			}
		}
	}

	// Process all clauses
	for _, clause := range allSlice {
		clauseMap, ok := clause.(map[string]interface{})
		if !ok {
			continue
		}
		if resources := util.SafeNestedMap(clauseMap, "resources"); resources != nil {
			ns, tgt, sel := extractFromResources(resources)
			namespaces = append(namespaces, ns...)
			targets = append(targets, tgt...)
			if sel != nil && selector == nil {
				selector = sel
			}
		}
	}

	// Deduplicate namespaces
	namespaces = util.UniqueStrings(namespaces)

	return namespaces, targets, selector
}

// extractFromResources extracts info from a Kyverno resources block.
func extractFromResources(resources map[string]interface{}) (namespaces []string, targets []types.ResourceTarget, selector *metav1.LabelSelector) {
	// Extract namespaces
	namespaces = util.SafeNestedStringSlice(resources, "namespaces")

	// Extract kinds
	kinds := util.SafeNestedStringSlice(resources, "kinds")
	if len(kinds) > 0 {
		// Parse kinds - Kyverno uses "Group/Kind" or just "Kind" format
		var apiGroups []string
		var resourceNames []string

		for _, kind := range kinds {
			parts := strings.SplitN(kind, "/", 2)
			if len(parts) == 2 {
				apiGroups = append(apiGroups, parts[0])
				resourceNames = append(resourceNames, strings.ToLower(parts[1])+"s")
			} else {
				// Just kind, assume core API group
				resourceNames = append(resourceNames, strings.ToLower(kind)+"s")
			}
		}

		if len(resourceNames) > 0 {
			targets = append(targets, types.ResourceTarget{
				APIGroups: util.UniqueStrings(apiGroups),
				Resources: util.UniqueStrings(resourceNames),
			})
		}
	}

	// Extract selector
	selector = util.SafeNestedLabelSelector(resources, "selector")

	return namespaces, targets, selector
}

// buildRuleSummary creates a human-readable summary for a rule.
func buildRuleSummary(policyName, ruleName, ruleType, action string, targets []types.ResourceTarget, isClusterPolicy bool) string {
	policyType := "Policy"
	if isClusterPolicy {
		policyType = "ClusterPolicy"
	}

	actionVerb := "validates"
	switch ruleType {
	case "validate":
		switch strings.ToLower(action) {
		case "enforce":
			actionVerb = "enforces"
		case "audit":
			actionVerb = "audits"
		}
	case "mutate":
		actionVerb = "mutates"
	case "generate":
		actionVerb = "generates resources from"
	case "verifyImages":
		actionVerb = "verifies images for"
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

	return fmt.Sprintf("Kyverno %s %q rule %q %s %s", policyType, policyName, ruleName, actionVerb, resourceList)
}

// buildRuleDetails creates the details map for a rule.
func buildRuleDetails(rule map[string]interface{}, ruleType, action string, targets []types.ResourceTarget) map[string]interface{} {
	details := map[string]interface{}{
		"ruleType": ruleType,
		"action":   action,
	}

	if len(targets) > 0 {
		details["resourceTargets"] = targets
	}

	// Extract validation message if present
	if validate := util.SafeNestedMap(rule, "validate"); validate != nil {
		if msg := util.SafeStringFromMap(validate, "message"); msg != "" {
			details["validationMessage"] = msg
		}
	}

	return details
}

// buildTags creates tags for filtering.
func buildTags(ruleType, action string, isClusterPolicy bool) []string {
	tags := []string{
		"kyverno",
		"admission",
		ruleType,
	}

	if isClusterPolicy {
		tags = append(tags, "cluster-wide")
	}

	switch strings.ToLower(action) {
	case "enforce":
		tags = append(tags, "blocking")
	case "audit":
		tags = append(tags, "audit")
	}

	return tags
}

// buildRemediation creates remediation steps.
func buildRemediation(policyName, namespace string, isClusterPolicy bool) []types.RemediationStep {
	var getCmd string
	if isClusterPolicy {
		getCmd = fmt.Sprintf("kubectl get clusterpolicy %s -o yaml", policyName)
	} else {
		getCmd = fmt.Sprintf("kubectl get policy -n %s %s -o yaml", namespace, policyName)
	}

	return []types.RemediationStep{
		{
			Type:              "kubectl",
			Description:       "View the policy details",
			Command:           getCmd,
			RequiresPrivilege: "developer",
		},
		{
			Type:              "kubectl",
			Description:       "Check policy report for violations",
			Command:           "kubectl get policyreport -A -o wide",
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
			Description:       "Kyverno documentation",
			URL:               "https://kyverno.io/docs/",
			RequiresPrivilege: "developer",
		},
	}
}
