package networkpolicy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var gvr = schema.GroupVersionResource{
	Group:    "networking.k8s.io",
	Version:  "v1",
	Resource: "networkpolicies",
}

// Adapter parses native Kubernetes NetworkPolicy resources.
type Adapter struct{}

func New() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "networkpolicy"
}

func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvr}
}

func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		return nil, fmt.Errorf("networkpolicy %s/%s: missing spec", namespace, name)
	}

	var constraints []types.Constraint

	// Parse policy types to determine if this is ingress, egress, or both
	policyTypes := extractPolicyTypes(spec)

	// Parse pod selector (which pods this policy applies to)
	podSelector := extractLabelSelector(spec, "podSelector")

	// Parse ingress rules
	if containsPolicyType(policyTypes, "Ingress") || len(policyTypes) == 0 {
		c := types.Constraint{
			UID:                obj.GetUID(),
			Source:             gvr,
			Name:               name,
			Namespace:          namespace,
			AffectedNamespaces: []string{namespace},
			WorkloadSelector:   podSelector,
			ConstraintType:     types.ConstraintTypeNetworkIngress,
			Effect:             "restrict",
			Severity:           types.SeverityWarning,
			Summary:            buildIngressSummary(name, spec),
			RemediationHint:    fmt.Sprintf("Review NetworkPolicy %s/%s or contact your platform team", namespace, name),
			Details:            extractIngressDetails(spec),
			RawObject:          obj.DeepCopy(),
		}
		constraints = append(constraints, c)
	}

	// Parse egress rules
	if containsPolicyType(policyTypes, "Egress") {
		c := types.Constraint{
			UID:                obj.GetUID(),
			Source:             gvr,
			Name:               name,
			Namespace:          namespace,
			AffectedNamespaces: []string{namespace},
			WorkloadSelector:   podSelector,
			ConstraintType:     types.ConstraintTypeNetworkEgress,
			Effect:             "restrict",
			Severity:           types.SeverityWarning,
			Summary:            buildEgressSummary(name, spec),
			RemediationHint:    fmt.Sprintf("Review NetworkPolicy %s/%s or contact your platform team", namespace, name),
			Details:            extractEgressDetails(spec),
			RawObject:          obj.DeepCopy(),
		}
		constraints = append(constraints, c)
	}

	return constraints, nil
}

// extractPolicyTypes reads spec.policyTypes from the NetworkPolicy.
func extractPolicyTypes(spec map[string]interface{}) []string {
	return util.SafeNestedStringSlice(spec, "policyTypes")
}

// containsPolicyType checks if a policy type is in the list.
func containsPolicyType(policyTypes []string, target string) bool {
	for _, t := range policyTypes {
		if t == target {
			return true
		}
	}
	return false
}

// extractLabelSelector reads a label selector from the spec.
func extractLabelSelector(spec map[string]interface{}, field string) *metav1.LabelSelector {
	return util.SafeNestedLabelSelector(spec, field)
}

// buildIngressSummary creates a human-readable summary of ingress rules.
func buildIngressSummary(name string, spec map[string]interface{}) string {
	ingress := util.SafeNestedSlice(spec, "ingress")
	if len(ingress) == 0 {
		return fmt.Sprintf("NetworkPolicy %q denies all ingress traffic", name)
	}
	return fmt.Sprintf("NetworkPolicy %q restricts ingress to %d rule(s)", name, len(ingress))
}

// buildEgressSummary creates a human-readable summary of egress rules.
func buildEgressSummary(name string, spec map[string]interface{}) string {
	egress := util.SafeNestedSlice(spec, "egress")
	if len(egress) == 0 {
		return fmt.Sprintf("NetworkPolicy %q denies all egress traffic", name)
	}
	return fmt.Sprintf("NetworkPolicy %q restricts egress to %d rule(s)", name, len(egress))
}

// extractIngressDetails pulls ingress-specific details for the Details map.
func extractIngressDetails(spec map[string]interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	ingress := util.SafeNestedSlice(spec, "ingress")
	if ingress == nil {
		details["ruleCount"] = 0
		details["deniesAll"] = true
		return details
	}

	details["ruleCount"] = len(ingress)
	var ports []string
	var cidrs []string

	for _, ruleRaw := range ingress {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ports = append(ports, extractPorts(rule)...)
		cidrs = append(cidrs, extractCIDRsFromRule(rule, "from")...)
	}

	if len(ports) > 0 {
		details["allowedPorts"] = uniqueStrings(ports)
	}
	if len(cidrs) > 0 {
		details["allowedCIDRs"] = uniqueStrings(cidrs)
	}
	return details
}

// extractEgressDetails pulls egress-specific details for the Details map.
func extractEgressDetails(spec map[string]interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	egress := util.SafeNestedSlice(spec, "egress")
	if egress == nil {
		details["ruleCount"] = 0
		details["deniesAll"] = true
		return details
	}

	details["ruleCount"] = len(egress)
	var ports []string
	var cidrs []string

	for _, ruleRaw := range egress {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ports = append(ports, extractPorts(rule)...)
		cidrs = append(cidrs, extractCIDRsFromRule(rule, "to")...)
	}

	if len(ports) > 0 {
		details["allowedPorts"] = uniqueStrings(ports)
	}
	if len(cidrs) > 0 {
		details["allowedCIDRs"] = uniqueStrings(cidrs)
	}
	return details
}

// extractPorts extracts port specifications from a rule.
func extractPorts(rule map[string]interface{}) []string {
	var ports []string
	portsRaw := util.SafeNestedSlice(rule, "ports")
	for _, portRaw := range portsRaw {
		portMap, ok := portRaw.(map[string]interface{})
		if !ok {
			continue
		}
		protocol := util.SafeStringFromMap(portMap, "protocol")
		if protocol == "" {
			protocol = "TCP"
		}
		// Port can be int or string
		var portStr string
		if portVal, ok := portMap["port"]; ok {
			switch v := portVal.(type) {
			case int64:
				portStr = fmt.Sprintf("%d", v)
			case float64:
				portStr = fmt.Sprintf("%d", int64(v))
			case string:
				portStr = v
			}
		}
		if portStr != "" {
			ports = append(ports, fmt.Sprintf("%s/%s", portStr, protocol))
		}
	}
	return ports
}

// extractCIDRsFromRule extracts CIDR blocks from ipBlock selectors.
func extractCIDRsFromRule(rule map[string]interface{}, direction string) []string {
	var cidrs []string
	peersRaw := util.SafeNestedSlice(rule, direction)
	for _, peerRaw := range peersRaw {
		peer, ok := peerRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ipBlockMap := util.SafeNestedMap(peer, "ipBlock")
		if ipBlockMap == nil {
			continue
		}
		cidr := util.SafeStringFromMap(ipBlockMap, "cidr")
		if cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// uniqueStrings returns a deduplicated copy of the slice.
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
