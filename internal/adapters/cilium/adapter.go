package cilium

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

var (
	gvrCNP = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}
	gvrCCNP = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}
)

// Adapter parses Cilium network policies.
type Adapter struct{}

// New creates a new Cilium adapter.
func New() *Adapter {
	return &Adapter{}
}

// Name returns the adapter identifier.
func (a *Adapter) Name() string {
	return "cilium"
}

// Handles returns the GVRs this adapter can parse.
func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvrCNP, gvrCCNP}
}

// Parse converts a Cilium network policy into normalized Constraints.
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()

	// Determine if cluster-wide
	gvk := obj.GroupVersionKind()
	isClusterWide := gvk.Kind == "CiliumClusterwideNetworkPolicy"
	source := gvrCNP
	if isClusterWide {
		source = gvrCCNP
	}

	// Get specs - CNP can have specs or spec
	specs := getSpecs(obj)
	if len(specs) == 0 {
		return nil, fmt.Errorf("cilium policy %s: missing spec or specs", name)
	}

	var constraints []types.Constraint

	for _, spec := range specs {
		// Parse endpoint selector (which pods this policy applies to)
		endpointSelector := extractEndpointSelector(spec)

		// Determine affected namespaces
		affectedNamespaces := []string{}
		if !isClusterWide && namespace != "" {
			affectedNamespaces = []string{namespace}
		}

		// Parse ingress rules
		ingress := util.SafeNestedSlice(spec, "ingress")
		ingressDeny := util.SafeNestedSlice(spec, "ingressDeny")
		hasIngress := len(ingress) > 0 || len(ingressDeny) > 0

		if hasIngress {
			severity := types.SeverityWarning
			effect := "restrict"
			if len(ingressDeny) > 0 {
				severity = types.SeverityCritical
				effect = "deny"
			}

			c := types.Constraint{
				UID:                obj.GetUID(),
				Source:             source,
				Name:               name,
				Namespace:          namespace,
				AffectedNamespaces: affectedNamespaces,
				WorkloadSelector:   endpointSelector,
				ConstraintType:     types.ConstraintTypeNetworkIngress,
				Effect:             effect,
				Severity:           severity,
				Summary:            buildIngressSummary(name, ingress, ingressDeny, isClusterWide),
				RemediationHint:    buildRemediationHint(name, namespace, isClusterWide),
				Details:            extractIngressDetails(ingress, ingressDeny),
				RawObject:          obj.DeepCopy(),
			}
			constraints = append(constraints, c)
		}

		// Parse egress rules
		egress := util.SafeNestedSlice(spec, "egress")
		egressDeny := util.SafeNestedSlice(spec, "egressDeny")
		hasEgress := len(egress) > 0 || len(egressDeny) > 0

		if hasEgress {
			severity := types.SeverityWarning
			effect := "restrict"
			if len(egressDeny) > 0 {
				severity = types.SeverityCritical
				effect = "deny"
			}

			c := types.Constraint{
				UID:                obj.GetUID(),
				Source:             source,
				Name:               name,
				Namespace:          namespace,
				AffectedNamespaces: affectedNamespaces,
				WorkloadSelector:   endpointSelector,
				ConstraintType:     types.ConstraintTypeNetworkEgress,
				Effect:             effect,
				Severity:           severity,
				Summary:            buildEgressSummary(name, egress, egressDeny, isClusterWide),
				RemediationHint:    buildRemediationHint(name, namespace, isClusterWide),
				Details:            extractEgressDetails(egress, egressDeny),
				RawObject:          obj.DeepCopy(),
			}
			constraints = append(constraints, c)
		}

		// If no ingress or egress rules, the policy is effectively a deny-all for selected pods
		if !hasIngress && !hasEgress {
			c := types.Constraint{
				UID:                obj.GetUID(),
				Source:             source,
				Name:               name,
				Namespace:          namespace,
				AffectedNamespaces: affectedNamespaces,
				WorkloadSelector:   endpointSelector,
				ConstraintType:     types.ConstraintTypeNetworkIngress,
				Effect:             "deny",
				Severity:           types.SeverityCritical,
				Summary:            fmt.Sprintf("CiliumNetworkPolicy %q denies all traffic to selected pods", name),
				RemediationHint:    buildRemediationHint(name, namespace, isClusterWide),
				Details:            map[string]interface{}{"deniesAll": true},
				RawObject:          obj.DeepCopy(),
			}
			constraints = append(constraints, c)
		}
	}

	return constraints, nil
}

// getSpecs returns the spec(s) from a Cilium policy.
// CiliumNetworkPolicy can have either "spec" (single) or "specs" (list).
func getSpecs(obj *unstructured.Unstructured) []map[string]interface{} {
	// Check for specs (array)
	if specs := util.SafeNestedSlice(obj.Object, "specs"); specs != nil {
		var result []map[string]interface{}
		for _, s := range specs {
			if m, ok := s.(map[string]interface{}); ok {
				result = append(result, m)
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Check for spec (single)
	if spec := util.SafeNestedMap(obj.Object, "spec"); spec != nil {
		return []map[string]interface{}{spec}
	}

	return nil
}

// extractEndpointSelector extracts the endpoint selector from the spec.
func extractEndpointSelector(spec map[string]interface{}) *metav1.LabelSelector {
	return util.SafeNestedLabelSelector(spec, "endpointSelector")
}

// buildIngressSummary creates a human-readable summary of ingress rules.
func buildIngressSummary(name string, ingress, ingressDeny []interface{}, isClusterWide bool) string {
	policyType := "CiliumNetworkPolicy"
	if isClusterWide {
		policyType = "CiliumClusterwideNetworkPolicy"
	}

	if len(ingressDeny) > 0 {
		return fmt.Sprintf("%s %q explicitly denies %d ingress source(s)", policyType, name, len(ingressDeny))
	}

	if len(ingress) == 0 {
		return fmt.Sprintf("%s %q denies all ingress traffic", policyType, name)
	}

	// Count entities and endpoints
	entities := []string{}
	var hasL7 bool
	for _, ruleRaw := range ingress {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		entities = append(entities, extractEntities(rule, "fromEntities")...)
		if hasL7Rules(rule) {
			hasL7 = true
		}
	}

	if len(entities) > 0 {
		uniqueEntities := uniqueStrings(entities)
		entityStr := strings.Join(uniqueEntities, ", ")
		if hasL7 {
			return fmt.Sprintf("%s %q allows ingress from %s with L7 filtering", policyType, name, entityStr)
		}
		return fmt.Sprintf("%s %q allows ingress from %s", policyType, name, entityStr)
	}

	if hasL7 {
		return fmt.Sprintf("%s %q restricts ingress with L7 rules (%d rule(s))", policyType, name, len(ingress))
	}
	return fmt.Sprintf("%s %q restricts ingress to %d rule(s)", policyType, name, len(ingress))
}

// buildEgressSummary creates a human-readable summary of egress rules.
func buildEgressSummary(name string, egress, egressDeny []interface{}, isClusterWide bool) string {
	policyType := "CiliumNetworkPolicy"
	if isClusterWide {
		policyType = "CiliumClusterwideNetworkPolicy"
	}

	if len(egressDeny) > 0 {
		return fmt.Sprintf("%s %q explicitly denies %d egress destination(s)", policyType, name, len(egressDeny))
	}

	if len(egress) == 0 {
		return fmt.Sprintf("%s %q denies all egress traffic", policyType, name)
	}

	// Count entities and FQDNs
	entities := []string{}
	fqdns := []string{}
	var hasL7 bool
	for _, ruleRaw := range egress {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		entities = append(entities, extractEntities(rule, "toEntities")...)
		fqdns = append(fqdns, extractFQDNs(rule)...)
		if hasL7Rules(rule) {
			hasL7 = true
		}
	}

	parts := []string{}
	if len(entities) > 0 {
		uniqueEntities := uniqueStrings(entities)
		parts = append(parts, strings.Join(uniqueEntities, ", "))
	}
	if len(fqdns) > 0 {
		uniqueFQDNs := uniqueStrings(fqdns)
		if len(uniqueFQDNs) <= 3 {
			parts = append(parts, strings.Join(uniqueFQDNs, ", "))
		} else {
			parts = append(parts, fmt.Sprintf("%d FQDN(s)", len(uniqueFQDNs)))
		}
	}

	if len(parts) > 0 {
		destStr := strings.Join(parts, " and ")
		if hasL7 {
			return fmt.Sprintf("%s %q allows egress to %s with L7 filtering", policyType, name, destStr)
		}
		return fmt.Sprintf("%s %q allows egress to %s", policyType, name, destStr)
	}

	if hasL7 {
		return fmt.Sprintf("%s %q restricts egress with L7 rules (%d rule(s))", policyType, name, len(egress))
	}
	return fmt.Sprintf("%s %q restricts egress to %d rule(s)", policyType, name, len(egress))
}

// buildRemediationHint creates the remediation hint.
func buildRemediationHint(name, namespace string, isClusterWide bool) string {
	if isClusterWide {
		return fmt.Sprintf("Review CiliumClusterwideNetworkPolicy %q or contact your platform team", name)
	}
	return fmt.Sprintf("Review CiliumNetworkPolicy %s/%s or contact your platform team", namespace, name)
}

// extractIngressDetails extracts ingress-specific details.
func extractIngressDetails(ingress, ingressDeny []interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	details["allowRuleCount"] = len(ingress)
	details["denyRuleCount"] = len(ingressDeny)

	var ports []string
	var entities []string
	var cidrs []string
	var l7Types []string

	for _, ruleRaw := range append(ingress, ingressDeny...) {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ports = append(ports, extractPorts(rule)...)
		entities = append(entities, extractEntities(rule, "fromEntities")...)
		cidrs = append(cidrs, extractCIDRs(rule, "fromCIDR", "fromCIDRSet")...)
		l7Types = append(l7Types, extractL7Types(rule)...)
	}

	if len(ports) > 0 {
		details["ports"] = uniqueStrings(ports)
	}
	if len(entities) > 0 {
		details["entities"] = uniqueStrings(entities)
	}
	if len(cidrs) > 0 {
		details["cidrs"] = uniqueStrings(cidrs)
	}
	if len(l7Types) > 0 {
		details["l7Types"] = uniqueStrings(l7Types)
	}

	return details
}

// extractEgressDetails extracts egress-specific details.
func extractEgressDetails(egress, egressDeny []interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	details["allowRuleCount"] = len(egress)
	details["denyRuleCount"] = len(egressDeny)

	var ports []string
	var entities []string
	var cidrs []string
	var fqdns []string
	var l7Types []string

	for _, ruleRaw := range append(egress, egressDeny...) {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ports = append(ports, extractPorts(rule)...)
		entities = append(entities, extractEntities(rule, "toEntities")...)
		cidrs = append(cidrs, extractCIDRs(rule, "toCIDR", "toCIDRSet")...)
		fqdns = append(fqdns, extractFQDNs(rule)...)
		l7Types = append(l7Types, extractL7Types(rule)...)
	}

	if len(ports) > 0 {
		details["ports"] = uniqueStrings(ports)
	}
	if len(entities) > 0 {
		details["entities"] = uniqueStrings(entities)
	}
	if len(cidrs) > 0 {
		details["cidrs"] = uniqueStrings(cidrs)
	}
	if len(fqdns) > 0 {
		details["fqdns"] = uniqueStrings(fqdns)
	}
	if len(l7Types) > 0 {
		details["l7Types"] = uniqueStrings(l7Types)
	}

	return details
}

// extractPorts extracts port specifications from a rule.
func extractPorts(rule map[string]interface{}) []string {
	var ports []string
	toPorts := util.SafeNestedSlice(rule, "toPorts")
	for _, portRaw := range toPorts {
		portMap, ok := portRaw.(map[string]interface{})
		if !ok {
			continue
		}
		portsSlice := util.SafeNestedSlice(portMap, "ports")
		for _, pRaw := range portsSlice {
			p, ok := pRaw.(map[string]interface{})
			if !ok {
				continue
			}
			protocol := util.SafeStringFromMap(p, "protocol")
			if protocol == "" {
				protocol = "TCP"
			}
			port := util.SafeStringFromMap(p, "port")
			if port != "" {
				ports = append(ports, fmt.Sprintf("%s/%s", port, protocol))
			}
		}
	}
	return ports
}

// extractEntities extracts entity selectors from a rule.
func extractEntities(rule map[string]interface{}, field string) []string {
	return util.SafeNestedStringSlice(rule, field)
}

// extractCIDRs extracts CIDR blocks from a rule.
func extractCIDRs(rule map[string]interface{}, fields ...string) []string {
	var cidrs []string
	for _, field := range fields {
		// Direct CIDR list
		cidrList := util.SafeNestedStringSlice(rule, field)
		cidrs = append(cidrs, cidrList...)

		// CIDRSet with except
		cidrSetList := util.SafeNestedSlice(rule, field)
		for _, csRaw := range cidrSetList {
			cs, ok := csRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if cidr := util.SafeStringFromMap(cs, "cidr"); cidr != "" {
				cidrs = append(cidrs, cidr)
			}
		}
	}
	return cidrs
}

// extractFQDNs extracts FQDN selectors from a rule.
func extractFQDNs(rule map[string]interface{}) []string {
	var fqdns []string
	toFQDNs := util.SafeNestedSlice(rule, "toFQDNs")
	for _, fRaw := range toFQDNs {
		f, ok := fRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if matchName := util.SafeStringFromMap(f, "matchName"); matchName != "" {
			fqdns = append(fqdns, matchName)
		}
		if matchPattern := util.SafeStringFromMap(f, "matchPattern"); matchPattern != "" {
			fqdns = append(fqdns, matchPattern)
		}
	}
	return fqdns
}

// hasL7Rules checks if a rule contains L7 filtering.
func hasL7Rules(rule map[string]interface{}) bool {
	toPorts := util.SafeNestedSlice(rule, "toPorts")
	for _, portRaw := range toPorts {
		portMap, ok := portRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if rules := util.SafeNestedMap(portMap, "rules"); rules != nil {
			if _, hasHTTP := rules["http"]; hasHTTP {
				return true
			}
			if _, hasDNS := rules["dns"]; hasDNS {
				return true
			}
			if _, hasKafka := rules["kafka"]; hasKafka {
				return true
			}
			if _, hasL7 := rules["l7"]; hasL7 {
				return true
			}
			if _, hasL7Proto := rules["l7proto"]; hasL7Proto {
				return true
			}
		}
	}
	return false
}

// extractL7Types returns the types of L7 rules in use.
func extractL7Types(rule map[string]interface{}) []string {
	var l7Types []string
	toPorts := util.SafeNestedSlice(rule, "toPorts")
	for _, portRaw := range toPorts {
		portMap, ok := portRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if rules := util.SafeNestedMap(portMap, "rules"); rules != nil {
			if _, hasHTTP := rules["http"]; hasHTTP {
				l7Types = append(l7Types, "http")
			}
			if _, hasDNS := rules["dns"]; hasDNS {
				l7Types = append(l7Types, "dns")
			}
			if _, hasKafka := rules["kafka"]; hasKafka {
				l7Types = append(l7Types, "kafka")
			}
			if proto := util.SafeStringFromMap(rules, "l7proto"); proto != "" {
				l7Types = append(l7Types, proto)
			}
		}
	}
	return l7Types
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
