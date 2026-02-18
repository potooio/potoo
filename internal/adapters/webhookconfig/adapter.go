package webhookconfig

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

var (
	validatingGVR = schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "validatingwebhookconfigurations",
	}
	mutatingGVR = schema.GroupVersionResource{
		Group:    "admissionregistration.k8s.io",
		Version:  "v1",
		Resource: "mutatingwebhookconfigurations",
	}
)

// Adapter parses ValidatingWebhookConfiguration and MutatingWebhookConfiguration resources.
type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "webhookconfig"
}

func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{validatingGVR, mutatingGVR}
}

func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	kind := obj.GetKind()

	webhooks := util.SafeNestedSlice(obj.Object, "webhooks")
	if len(webhooks) == 0 {
		return nil, nil
	}

	// Determine GVR based on kind
	var sourceGVR schema.GroupVersionResource
	var webhookType string
	if kind == "ValidatingWebhookConfiguration" {
		sourceGVR = validatingGVR
		webhookType = "Validating"
	} else {
		sourceGVR = mutatingGVR
		webhookType = "Mutating"
	}

	var constraints []types.Constraint

	for i, webhookRaw := range webhooks {
		webhookMap, ok := webhookRaw.(map[string]interface{})
		if !ok {
			continue
		}

		webhookName := util.SafeStringFromMap(webhookMap, "name")

		// Skip potoo-owned webhooks
		if shouldSkipWebhook(webhookMap, webhookName) {
			continue
		}

		failurePolicy := util.SafeStringFromMap(webhookMap, "failurePolicy")
		if failurePolicy == "" {
			failurePolicy = "Fail" // K8s default
		}

		// Parse rules to extract operations and resources
		rules := util.SafeNestedSlice(webhookMap, "rules")
		operations, resources, resourceTargets := parseRules(rules)

		// Parse namespaceSelector
		namespaceSelector := util.SafeNestedLabelSelector(webhookMap, "namespaceSelector")

		// Determine severity based on failurePolicy
		severity := types.SeverityInfo
		if failurePolicy == "Fail" {
			severity = types.SeverityWarning
		}

		// Create unique UID
		uid := k8stypes.UID(fmt.Sprintf("%s-%d", obj.GetUID(), i))

		details := map[string]interface{}{
			"webhookName":   webhookName,
			"webhookType":   webhookType,
			"failurePolicy": failurePolicy,
		}
		if len(operations) > 0 {
			details["operations"] = operations
		}
		if len(resources) > 0 {
			details["resources"] = resources
		}

		c := types.Constraint{
			UID:               uid,
			Source:            sourceGVR,
			Name:              fmt.Sprintf("%s-%s", name, webhookName),
			Namespace:         "", // cluster-scoped
			NamespaceSelector: namespaceSelector,
			ResourceTargets:   resourceTargets,
			ConstraintType:    types.ConstraintTypeAdmission,
			Effect:            "intercept",
			Severity:          severity,
			Summary:           buildWebhookSummary(webhookType, webhookName, operations, resources),
			RemediationHint:   fmt.Sprintf("Check webhook %q logs if requests are being rejected", webhookName),
			Details:           details,
			RawObject:         obj.DeepCopy(),
		}

		constraints = append(constraints, c)
	}

	return constraints, nil
}

// shouldSkipWebhook returns true if this is a potoo-owned webhook.
func shouldSkipWebhook(webhookMap map[string]interface{}, webhookName string) bool {
	// Skip if name contains "potoo"
	if strings.Contains(strings.ToLower(webhookName), "potoo") {
		return true
	}

	// Skip if clientConfig.service.name contains "potoo"
	clientConfig := util.SafeNestedMap(webhookMap, "clientConfig")
	if clientConfig != nil {
		service := util.SafeNestedMap(clientConfig, "service")
		if service != nil {
			serviceName := util.SafeStringFromMap(service, "name")
			if strings.Contains(strings.ToLower(serviceName), "potoo") {
				return true
			}
		}
	}

	return false
}

// parseRules extracts operations, resources, and ResourceTargets from webhook rules.
func parseRules(rules []interface{}) ([]string, []string, []types.ResourceTarget) {
	operationSet := make(map[string]bool)
	resourceSet := make(map[string]bool)
	var resourceTargets []types.ResourceTarget

	for _, ruleRaw := range rules {
		ruleMap, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract operations
		ops := util.SafeNestedStringSlice(ruleMap, "operations")
		for _, op := range ops {
			operationSet[op] = true
		}

		// Extract apiGroups and resources for ResourceTargets
		apiGroups := util.SafeNestedStringSlice(ruleMap, "apiGroups")
		resources := util.SafeNestedStringSlice(ruleMap, "resources")

		for _, r := range resources {
			resourceSet[r] = true
		}

		if len(apiGroups) > 0 && len(resources) > 0 {
			resourceTargets = append(resourceTargets, types.ResourceTarget{
				APIGroups: apiGroups,
				Resources: resources,
			})
		}
	}

	// Convert sets to sorted slices
	operations := setToSortedSlice(operationSet)
	resourceList := setToSortedSlice(resourceSet)

	return operations, resourceList, resourceTargets
}

// setToSortedSlice converts a set to a sorted slice.
func setToSortedSlice(set map[string]bool) []string {
	var result []string
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

// buildWebhookSummary creates a human-readable summary.
func buildWebhookSummary(webhookType, webhookName string, operations, resources []string) string {
	var parts []string

	if len(operations) > 0 {
		parts = append(parts, strings.Join(operations, ","))
	}

	if len(resources) > 0 {
		parts = append(parts, "on "+strings.Join(resources, ", "))
	}

	if len(parts) > 0 {
		return fmt.Sprintf("%s webhook %q intercepts %s", webhookType, webhookName, strings.Join(parts, " "))
	}
	return fmt.Sprintf("%s webhook %q", webhookType, webhookName)
}
