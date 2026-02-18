package notifier

import (
	"fmt"
	"strings"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/types"
)

// RemediationBuilder converts Constraint remediation data to structured RemediationInfo.
type RemediationBuilder struct {
	// DefaultContact is used when no specific contact is available.
	DefaultContact string
}

// NewRemediationBuilder creates a new RemediationBuilder.
func NewRemediationBuilder(defaultContact string) *RemediationBuilder {
	if defaultContact == "" {
		defaultContact = "your platform team"
	}
	return &RemediationBuilder{DefaultContact: defaultContact}
}

// Build converts a Constraint's remediation information to a structured RemediationInfo.
// It generates adapter-specific remediation steps based on the constraint type and source.
func (rb *RemediationBuilder) Build(c types.Constraint) v1alpha1.RemediationInfo {
	// If constraint already has structured remediation steps, convert them
	if len(c.Remediation) > 0 {
		return rb.convertSteps(c)
	}

	// Generate adapter-specific remediation based on constraint type and source
	switch {
	case isNetworkPolicySource(c):
		return rb.buildNetworkPolicyRemediation(c)
	case isResourceQuotaSource(c):
		return rb.buildResourceQuotaRemediation(c)
	case isWebhookSource(c):
		return rb.buildWebhookRemediation(c)
	case c.ConstraintType == types.ConstraintTypeMissing:
		return rb.buildMissingResourceRemediation(c)
	default:
		return rb.buildGenericRemediation(c)
	}
}

// convertSteps converts types.RemediationStep slice to v1alpha1.RemediationStep slice.
func (rb *RemediationBuilder) convertSteps(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: c.RemediationHint,
	}
	if info.Summary == "" {
		info.Summary = rb.generateSummary(c)
	}

	for _, step := range c.Remediation {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              step.Type,
			Description:       step.Description,
			Command:           step.Command,
			Patch:             step.Patch,
			Template:          step.Template,
			URL:               step.URL,
			Contact:           step.Contact,
			RequiresPrivilege: step.RequiresPrivilege,
		})
	}

	return info
}

// buildNetworkPolicyRemediation generates remediation steps for NetworkPolicy constraints.
func (rb *RemediationBuilder) buildNetworkPolicyRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: rb.generateSummary(c),
	}

	// Step 1: Inspect the network policy
	if c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "Inspect the NetworkPolicy to understand the allowed traffic",
			Command:           fmt.Sprintf("kubectl get networkpolicy %s -n %s -o yaml", c.Name, c.Namespace),
			RequiresPrivilege: "developer",
		})
	}

	// Step 2: Describe for events
	if c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "Check for related events in the namespace",
			Command:           fmt.Sprintf("kubectl get events -n %s --field-selector reason=NetworkPolicyDrop", c.Namespace),
			RequiresPrivilege: "developer",
		})
	}

	// Step 3: Contact platform team for exceptions
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "manual",
		Description:       "Request a network policy exception or modification",
		Contact:           rb.resolveContact(c),
		RequiresPrivilege: "namespace-admin",
	})

	// Step 4: Link to docs if available
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "link",
		Description:       "Review network policy documentation",
		URL:               "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
		RequiresPrivilege: "developer",
	})

	return info
}

// buildResourceQuotaRemediation generates remediation steps for ResourceQuota constraints.
func (rb *RemediationBuilder) buildResourceQuotaRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: rb.generateSummary(c),
	}

	// Step 1: Describe the quota to see current usage
	if c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "View current quota usage",
			Command:           fmt.Sprintf("kubectl describe resourcequota %s -n %s", c.Name, c.Namespace),
			RequiresPrivilege: "developer",
		})
	}

	// Step 2: Check resource requests in the namespace
	if c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "List pods with resource requests to identify optimization opportunities",
			Command:           fmt.Sprintf("kubectl get pods -n %s -o custom-columns='NAME:.metadata.name,CPU_REQ:.spec.containers[*].resources.requests.cpu,MEM_REQ:.spec.containers[*].resources.requests.memory'", c.Namespace),
			RequiresPrivilege: "developer",
		})
	}

	// Step 3: Request quota increase
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "manual",
		Description:       "Request a quota increase from your platform team",
		Contact:           rb.resolveContact(c),
		RequiresPrivilege: "namespace-admin",
	})

	// Step 4: Optimize resource usage
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "link",
		Description:       "Review resource management best practices",
		URL:               "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
		RequiresPrivilege: "developer",
	})

	return info
}

// buildWebhookRemediation generates remediation steps for admission webhook constraints.
func (rb *RemediationBuilder) buildWebhookRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: rb.generateSummary(c),
	}

	// Determine webhook config name (strip the webhook name suffix)
	configName := c.Name
	if idx := strings.LastIndex(c.Name, "-"); idx > 0 {
		configName = c.Name[:idx]
	}

	// Step 1: Inspect the webhook configuration
	webhookKind := "validatingwebhookconfigurations"
	if c.Source.Resource == "mutatingwebhookconfigurations" {
		webhookKind = "mutatingwebhookconfigurations"
	}

	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "kubectl",
		Description:       "Inspect the webhook configuration",
		Command:           fmt.Sprintf("kubectl get %s %s -o yaml", webhookKind, configName),
		RequiresPrivilege: "cluster-admin",
	})

	// Step 2: Check webhook logs
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "manual",
		Description:       "Check the webhook service logs for rejection details",
		Contact:           rb.resolveContact(c),
		RequiresPrivilege: "cluster-admin",
	})

	// Step 3: Dry-run to test
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "kubectl",
		Description:       "Test resource creation with dry-run to see webhook response",
		Command:           "kubectl apply --dry-run=server -f <your-manifest.yaml>",
		RequiresPrivilege: "developer",
	})

	// Step 4: Documentation
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "link",
		Description:       "Review admission webhook documentation",
		URL:               "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/",
		RequiresPrivilege: "developer",
	})

	return info
}

// buildMissingResourceRemediation generates remediation steps for missing resource constraints.
func (rb *RemediationBuilder) buildMissingResourceRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: rb.generateSummary(c),
	}

	// Extract expected resource kind from details if available
	expectedKind := ""
	expectedAPIVersion := ""
	if c.Details != nil {
		if kind, ok := c.Details["expectedKind"].(string); ok {
			expectedKind = kind
		}
		if apiVersion, ok := c.Details["expectedAPIVersion"].(string); ok {
			expectedAPIVersion = apiVersion
		}
	}

	// Step 1: Check if the resource exists
	if expectedKind != "" && c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       fmt.Sprintf("Check if %s resources exist in your namespace", expectedKind),
			Command:           fmt.Sprintf("kubectl get %s -n %s", strings.ToLower(expectedKind), c.Namespace),
			RequiresPrivilege: "developer",
		})
	}

	// Step 2: Provide template if available
	if template := rb.getMissingResourceTemplate(expectedKind, expectedAPIVersion, c); template != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "yaml_patch",
			Description:       fmt.Sprintf("Create the missing %s resource", expectedKind),
			Template:          template,
			RequiresPrivilege: "developer",
		})
	}

	// Step 3: Contact for help
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "manual",
		Description:       "Contact your platform team for guidance on creating this resource",
		Contact:           rb.resolveContact(c),
		RequiresPrivilege: "developer",
	})

	return info
}

// buildGenericRemediation generates generic remediation steps for unknown constraint types.
func (rb *RemediationBuilder) buildGenericRemediation(c types.Constraint) v1alpha1.RemediationInfo {
	info := v1alpha1.RemediationInfo{
		Summary: rb.generateSummary(c),
	}

	// Step 1: View the constraint source
	if c.Namespace != "" {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "Inspect the constraint source object",
			Command:           fmt.Sprintf("kubectl get %s %s -n %s -o yaml", c.Source.Resource, c.Name, c.Namespace),
			RequiresPrivilege: "developer",
		})
	} else {
		info.Steps = append(info.Steps, v1alpha1.RemediationStep{
			Type:              "kubectl",
			Description:       "Inspect the constraint source object",
			Command:           fmt.Sprintf("kubectl get %s %s -o yaml", c.Source.Resource, c.Name),
			RequiresPrivilege: "cluster-admin",
		})
	}

	// Step 2: Contact platform team
	info.Steps = append(info.Steps, v1alpha1.RemediationStep{
		Type:              "manual",
		Description:       "Contact your platform team for assistance with this constraint",
		Contact:           rb.resolveContact(c),
		RequiresPrivilege: "developer",
	})

	return info
}

// generateSummary creates a human-readable summary of the remediation.
func (rb *RemediationBuilder) generateSummary(c types.Constraint) string {
	if c.RemediationHint != "" {
		return c.RemediationHint
	}

	switch c.ConstraintType {
	case types.ConstraintTypeNetworkIngress:
		return "Review network policy or request ingress exception"
	case types.ConstraintTypeNetworkEgress:
		return "Review network policy or request egress exception"
	case types.ConstraintTypeAdmission:
		return "Review admission policy requirements or request exception"
	case types.ConstraintTypeResourceLimit:
		return "Optimize resource usage or request quota increase"
	case types.ConstraintTypeMeshPolicy:
		return "Review service mesh policy configuration"
	case types.ConstraintTypeMissing:
		return "Create the missing companion resource"
	default:
		return fmt.Sprintf("Contact %s for assistance", rb.DefaultContact)
	}
}

// resolveContact returns the appropriate contact for the constraint.
func (rb *RemediationBuilder) resolveContact(c types.Constraint) string {
	// Check if constraint has specific contact in details
	if c.Details != nil {
		if contact, ok := c.Details["contact"].(string); ok && contact != "" {
			return contact
		}
	}

	// Check RemediationHint for contact info (legacy)
	if strings.Contains(c.RemediationHint, "@") || strings.Contains(c.RemediationHint, "#") {
		return c.RemediationHint
	}

	return rb.DefaultContact
}

// getMissingResourceTemplate returns a YAML template for common missing resources.
func (rb *RemediationBuilder) getMissingResourceTemplate(kind, apiVersion string, c types.Constraint) string {
	switch kind {
	case "ServiceMonitor":
		return `apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {workload_name}
  namespace: {namespace}
spec:
  selector:
    matchLabels:
      app: {workload_name}
  endpoints:
  - port: metrics
    interval: 30s`

	case "VirtualService":
		return `apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: {workload_name}
  namespace: {namespace}
spec:
  hosts:
  - {workload_name}
  http:
  - route:
    - destination:
        host: {workload_name}
        port:
          number: 80`

	case "DestinationRule":
		return `apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: {workload_name}
  namespace: {namespace}
spec:
  host: {workload_name}
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL`

	case "PodDisruptionBudget":
		return `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {workload_name}
  namespace: {namespace}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: {workload_name}`

	case "HorizontalPodAutoscaler":
		return `apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {workload_name}
  namespace: {namespace}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {workload_name}
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 80`

	default:
		return ""
	}
}

// isNetworkPolicySource returns true if the constraint comes from a NetworkPolicy.
func isNetworkPolicySource(c types.Constraint) bool {
	return c.Source.Resource == "networkpolicies" ||
		c.Source.Resource == "ciliumnetworkpolicies" ||
		c.Source.Resource == "ciliumclusterwidenetworkpolicies"
}

// isResourceQuotaSource returns true if the constraint comes from a ResourceQuota.
func isResourceQuotaSource(c types.Constraint) bool {
	return c.Source.Resource == "resourcequotas" || c.Source.Resource == "limitranges"
}

// isWebhookSource returns true if the constraint comes from a webhook configuration.
func isWebhookSource(c types.Constraint) bool {
	return c.Source.Resource == "validatingwebhookconfigurations" ||
		c.Source.Resource == "mutatingwebhookconfigurations"
}
