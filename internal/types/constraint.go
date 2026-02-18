package types

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// ConstraintType categorizes the kind of constraint.
type ConstraintType string

const (
	ConstraintTypeNetworkIngress ConstraintType = "NetworkIngress"
	ConstraintTypeNetworkEgress  ConstraintType = "NetworkEgress"
	ConstraintTypeAdmission      ConstraintType = "Admission"
	ConstraintTypeResourceLimit  ConstraintType = "ResourceLimit"
	ConstraintTypeMeshPolicy     ConstraintType = "MeshPolicy"
	ConstraintTypeMissing        ConstraintType = "MissingResource"
	ConstraintTypeUnknown        ConstraintType = "Unknown"
)

// Severity indicates how urgently a constraint issue needs attention.
type Severity string

const (
	SeverityCritical Severity = "Critical" // Active traffic drops, admission rejections
	SeverityWarning  Severity = "Warning"  // Audit violations, approaching limits, missing resources
	SeverityInfo     Severity = "Info"     // Informational, not actively blocking
)

// DetailLevel controls how much information is included in notifications.
type DetailLevel string

const (
	DetailLevelSummary  DetailLevel = "summary"  // Developer-safe, no cross-namespace details
	DetailLevelDetailed DetailLevel = "detailed" // Namespace admin, includes ports and effect details
	DetailLevelFull     DetailLevel = "full"     // Platform admin, complete constraint details
)

// Constraint is the normalized, engine-agnostic representation of a policy,
// quota, webhook, or other constraint discovered in the cluster.
type Constraint struct {
	// Identity
	UID       types.UID
	Source    schema.GroupVersionResource
	Name      string
	Namespace string // empty = cluster-scoped

	// Scope — which workloads does this constraint affect?
	AffectedNamespaces []string
	NamespaceSelector  *metav1.LabelSelector
	WorkloadSelector   *metav1.LabelSelector
	ResourceTargets    []ResourceTarget // which resource types (for admission constraints)

	// Effect
	ConstraintType ConstraintType
	Effect         string // deny, restrict, warn, audit, limit
	Severity       Severity

	// Details — adapter-specific fields for full-detail notifications.
	// Examples: allowed ports, CIDR ranges, Rego source, quota values.
	// Keys should be well-known strings defined per adapter.
	Details map[string]interface{}

	// Human-readable strings for notifications
	Summary         string // e.g., "Restricts egress to ports 443, 8443"
	RemediationHint string // e.g., "Contact platform-team@company.com"

	// Remediation contains structured, actionable remediation steps.
	// Adapters populate this with typed steps that agents can execute.
	// Falls back to RemediationHint as a single "manual" step if empty.
	Remediation []RemediationStep

	// Tags for agent filtering (e.g., "network", "egress", "port-restriction").
	Tags []string

	// Reference back to the original Kubernetes object
	RawObject *unstructured.Unstructured
}

// RemediationStep is a single actionable step to resolve a constraint issue.
type RemediationStep struct {
	// Type: "manual", "kubectl", "annotation", "yaml_patch", "link"
	Type string

	// Description: human-readable explanation
	Description string

	// Command: kubectl command (when Type=kubectl)
	Command string

	// Patch: kubectl patch/annotate command (when Type=annotation or yaml_patch)
	Patch string

	// Template: YAML manifest template with {workload_name}, {namespace} placeholders
	Template string

	// URL: documentation or runbook link (when Type=link)
	URL string

	// Contact: email or Slack channel (when Type=manual)
	Contact string

	// RequiresPrivilege: "developer", "namespace-admin", "cluster-admin"
	RequiresPrivilege string
}

// ResourceTarget identifies a Kubernetes resource type that a constraint applies to.
type ResourceTarget struct {
	APIGroups []string
	Resources []string
}

// ConstraintQuery is used to query the constraint index.
type ConstraintQuery struct {
	Namespace      string
	Labels         map[string]string
	ConstraintType *ConstraintType
	Severity       *Severity
	SourceGVR      *schema.GroupVersionResource
}
