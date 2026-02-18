package istio

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
	gvrAuthorizationPolicy = schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "authorizationpolicies",
	}
	gvrPeerAuthentication = schema.GroupVersionResource{
		Group:    "security.istio.io",
		Version:  "v1",
		Resource: "peerauthentications",
	}
	gvrSidecar = schema.GroupVersionResource{
		Group:    "networking.istio.io",
		Version:  "v1",
		Resource: "sidecars",
	}
)

// Adapter parses Istio security and networking policies.
type Adapter struct{}

// New creates a new Istio adapter.
func New() *Adapter {
	return &Adapter{}
}

// Name returns the adapter identifier.
func (a *Adapter) Name() string {
	return "istio"
}

// Handles returns the GVRs this adapter can parse.
func (a *Adapter) Handles() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvrAuthorizationPolicy, gvrPeerAuthentication, gvrSidecar}
}

// Parse converts an Istio resource into normalized Constraints.
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) {
	switch obj.GetKind() {
	case "AuthorizationPolicy":
		return a.parseAuthorizationPolicy(obj)
	case "PeerAuthentication":
		return a.parsePeerAuthentication(obj)
	case "Sidecar":
		return a.parseSidecar(obj)
	default:
		return nil, fmt.Errorf("istio adapter: unsupported kind %q", obj.GetKind())
	}
}

// parseAuthorizationPolicy parses an Istio AuthorizationPolicy.
func (a *Adapter) parseAuthorizationPolicy(obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		spec = map[string]interface{}{}
	}

	// Istio defaults to ALLOW when action is omitted.
	action := strings.ToUpper(util.SafeStringFromMap(spec, "action"))
	if action == "" {
		action = "ALLOW"
	}

	effect := "restrict"
	severity := types.SeverityWarning
	if action == "DENY" {
		effect = "deny"
		severity = types.SeverityCritical
	}

	affectedNamespaces := []string{}
	if namespace != "" {
		affectedNamespaces = []string{namespace}
	}

	workloadSelector := util.SafeNestedLabelSelector(spec, "selector")

	summary := buildAuthzSummary(name, action, spec)
	details := extractAuthzDetails(action, spec)

	c := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvrAuthorizationPolicy,
		Name:               name,
		Namespace:          namespace,
		AffectedNamespaces: affectedNamespaces,
		WorkloadSelector:   workloadSelector,
		ConstraintType:     types.ConstraintTypeMeshPolicy,
		Effect:             effect,
		Severity:           severity,
		Summary:            summary,
		RemediationHint:    fmt.Sprintf("Review AuthorizationPolicy %s/%s or contact your platform team", namespace, name),
		Details:            details,
		Tags:               []string{"mesh", "istio", "authorization"},
		RawObject:          obj.DeepCopy(),
	}
	return []types.Constraint{c}, nil
}

// parsePeerAuthentication parses an Istio PeerAuthentication.
func (a *Adapter) parsePeerAuthentication(obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		spec = map[string]interface{}{}
	}

	// Parse mTLS mode; default is unset (empty string).
	mtlsMode := strings.ToUpper(util.SafeNestedString(spec, "mtls", "mode"))

	var effect string
	var severity types.Severity
	switch mtlsMode {
	case "STRICT":
		effect = "require"
		severity = types.SeverityWarning
	case "DISABLE":
		effect = "warn"
		severity = types.SeverityInfo
	default:
		// PERMISSIVE, UNSET, or empty — Istio inherits from parent; treat as informational.
		effect = "restrict"
		severity = types.SeverityInfo
	}

	// Determine scope.
	workloadSelector := util.SafeNestedLabelSelector(spec, "selector")
	scope := determinePeerAuthScope(namespace, workloadSelector)

	affectedNamespaces := []string{}
	if namespace != "" {
		affectedNamespaces = []string{namespace}
	}

	summary := buildPeerAuthSummary(name, mtlsMode, scope)
	details := map[string]interface{}{
		"mtlsMode": mtlsMode,
		"scope":    scope,
	}
	if portMtls := util.SafeNestedMap(spec, "portLevelMtls"); portMtls != nil {
		details["hasPortLevelMtls"] = true
	}

	c := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvrPeerAuthentication,
		Name:               name,
		Namespace:          namespace,
		AffectedNamespaces: affectedNamespaces,
		WorkloadSelector:   workloadSelector,
		ConstraintType:     types.ConstraintTypeMeshPolicy,
		Effect:             effect,
		Severity:           severity,
		Summary:            summary,
		RemediationHint:    fmt.Sprintf("Review PeerAuthentication %s/%s or contact your platform team", namespace, name),
		Details:            details,
		Tags:               []string{"mesh", "istio", "mtls"},
		RawObject:          obj.DeepCopy(),
	}
	return []types.Constraint{c}, nil
}

// parseSidecar parses an Istio Sidecar resource.
func (a *Adapter) parseSidecar(obj *unstructured.Unstructured) ([]types.Constraint, error) {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	spec := util.SafeNestedMap(obj.Object, "spec")
	if spec == nil {
		spec = map[string]interface{}{}
	}

	// Sidecar uses spec.workloadSelector.labels (flat map), not a K8s LabelSelector.
	workloadSelector := extractSidecarWorkloadSelector(spec)

	// Parse egress hosts.
	egressHosts := extractSidecarEgressHosts(spec)
	ingressPorts := extractSidecarIngressPorts(spec)

	effect := "restrict"

	affectedNamespaces := []string{}
	if namespace != "" {
		affectedNamespaces = []string{namespace}
	}

	summary := buildSidecarSummary(name, egressHosts, ingressPorts)
	details := map[string]interface{}{}
	if len(egressHosts) > 0 {
		details["egressHosts"] = egressHosts
	}
	if len(ingressPorts) > 0 {
		details["ingressPorts"] = ingressPorts
	}

	c := types.Constraint{
		UID:                obj.GetUID(),
		Source:             gvrSidecar,
		Name:               name,
		Namespace:          namespace,
		AffectedNamespaces: affectedNamespaces,
		WorkloadSelector:   workloadSelector,
		ConstraintType:     types.ConstraintTypeMeshPolicy,
		Effect:             effect,
		Severity:           types.SeverityInfo,
		Summary:            summary,
		RemediationHint:    fmt.Sprintf("Review Sidecar %s/%s or contact your platform team", namespace, name),
		Details:            details,
		Tags:               []string{"mesh", "istio", "sidecar"},
		RawObject:          obj.DeepCopy(),
	}
	return []types.Constraint{c}, nil
}

// --- AuthorizationPolicy helpers ---

func buildAuthzSummary(name, action string, spec map[string]interface{}) string {
	rules := util.SafeNestedSlice(spec, "rules")
	if len(rules) == 0 {
		switch action {
		case "DENY":
			return fmt.Sprintf("AuthorizationPolicy %q: DENY with no rules (no-op)", name)
		case "ALLOW":
			return fmt.Sprintf("AuthorizationPolicy %q: ALLOW with no rules (denies all traffic)", name)
		default:
			return fmt.Sprintf("AuthorizationPolicy %q: %s with no rules", name, action)
		}
	}

	sources, operations := summarizeRules(rules)

	parts := []string{fmt.Sprintf("AuthorizationPolicy %q", name)}
	if action == "DENY" {
		parts = append(parts, "denies traffic")
	} else {
		parts = append(parts, "restricts traffic")
	}
	if len(sources) > 0 {
		parts = append(parts, fmt.Sprintf("from %s", strings.Join(sources, ", ")))
	}
	if len(operations) > 0 {
		parts = append(parts, fmt.Sprintf("to %s", strings.Join(operations, ", ")))
	}
	return strings.Join(parts, " ")
}

func summarizeRules(rules []interface{}) (sources []string, operations []string) {
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		fromSlice := util.SafeNestedSlice(rule, "from")
		for _, fromRaw := range fromSlice {
			from, ok := fromRaw.(map[string]interface{})
			if !ok {
				continue
			}
			sourceMap := util.SafeNestedMap(from, "source")
			if sourceMap == nil {
				continue
			}
			principals := util.SafeNestedStringSlice(sourceMap, "principals")
			sources = append(sources, principals...)
			namespaces := util.SafeNestedStringSlice(sourceMap, "namespaces")
			for _, ns := range namespaces {
				sources = append(sources, fmt.Sprintf("namespace/%s", ns))
			}
		}

		toSlice := util.SafeNestedSlice(rule, "to")
		for _, toRaw := range toSlice {
			to, ok := toRaw.(map[string]interface{})
			if !ok {
				continue
			}
			operation := util.SafeNestedMap(to, "operation")
			if operation == nil {
				continue
			}
			methods := util.SafeNestedStringSlice(operation, "methods")
			operations = append(operations, methods...)
			paths := util.SafeNestedStringSlice(operation, "paths")
			operations = append(operations, paths...)
			ports := util.SafeNestedStringSlice(operation, "ports")
			for _, p := range ports {
				operations = append(operations, fmt.Sprintf("port/%s", p))
			}
		}
	}
	return uniqueStrings(sources), uniqueStrings(operations)
}

func extractAuthzDetails(action string, spec map[string]interface{}) map[string]interface{} {
	details := map[string]interface{}{
		"action": action,
	}
	rules := util.SafeNestedSlice(spec, "rules")
	details["ruleCount"] = len(rules)
	return details
}

// --- PeerAuthentication helpers ---

func determinePeerAuthScope(namespace string, selector *metav1.LabelSelector) string {
	if namespace == "" || namespace == "istio-system" {
		if selector == nil {
			return "mesh-wide"
		}
	}
	if selector == nil {
		return "namespace"
	}
	return "workload"
}

func buildPeerAuthSummary(name, mtlsMode, scope string) string {
	if mtlsMode == "" {
		mtlsMode = "UNSET"
	}
	return fmt.Sprintf("PeerAuthentication %q: mTLS %s (%s scope)", name, mtlsMode, scope)
}

// --- Sidecar helpers ---

// extractSidecarWorkloadSelector converts Istio's spec.workloadSelector.labels
// (a flat label map) into a Kubernetes LabelSelector.
func extractSidecarWorkloadSelector(spec map[string]interface{}) *metav1.LabelSelector {
	labelsMap := util.SafeNestedMap(spec, "workloadSelector", "labels")
	if labelsMap == nil {
		return nil
	}
	matchLabels := make(map[string]string)
	for k, v := range labelsMap {
		if s, ok := v.(string); ok {
			matchLabels[k] = s
		}
	}
	if len(matchLabels) == 0 {
		return nil
	}
	return &metav1.LabelSelector{MatchLabels: matchLabels}
}

func extractSidecarEgressHosts(spec map[string]interface{}) []string {
	var hosts []string
	egress := util.SafeNestedSlice(spec, "egress")
	for _, eRaw := range egress {
		e, ok := eRaw.(map[string]interface{})
		if !ok {
			continue
		}
		h := util.SafeNestedStringSlice(e, "hosts")
		hosts = append(hosts, h...)
	}
	return hosts
}

func extractSidecarIngressPorts(spec map[string]interface{}) []string {
	var ports []string
	ingress := util.SafeNestedSlice(spec, "ingress")
	for _, iRaw := range ingress {
		i, ok := iRaw.(map[string]interface{})
		if !ok {
			continue
		}
		port := util.SafeNestedMap(i, "port")
		if port == nil {
			continue
		}
		number := portNumberToString(port["number"])
		protocol := util.SafeStringFromMap(port, "protocol")
		name := util.SafeStringFromMap(port, "name")
		if number != "" {
			label := number
			if protocol != "" {
				label = fmt.Sprintf("%s/%s", number, protocol)
			}
			if name != "" {
				label = fmt.Sprintf("%s (%s)", label, name)
			}
			ports = append(ports, label)
		}
	}
	return ports
}

// portNumberToString converts a port number value to string.
// The Istio CRD defines port.number as uint32, so it may arrive as int64 or
// float64 from the dynamic client, not just as a string.
func portNumberToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%d", int64(v))
	default:
		return ""
	}
}

func buildSidecarSummary(name string, egressHosts, ingressPorts []string) string {
	parts := []string{fmt.Sprintf("Sidecar %q", name)}
	if len(egressHosts) > 0 {
		if len(egressHosts) <= 3 {
			parts = append(parts, fmt.Sprintf("restricts egress to %s", strings.Join(egressHosts, ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("restricts egress to %d host(s)", len(egressHosts)))
		}
	}
	if len(ingressPorts) > 0 {
		parts = append(parts, fmt.Sprintf("configures %d ingress port(s)", len(ingressPorts)))
	}
	if len(egressHosts) == 0 && len(ingressPorts) == 0 {
		parts = append(parts, "configures sidecar proxy")
	}
	return strings.Join(parts, " ")
}

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
