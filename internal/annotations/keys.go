// Package annotations defines the structured annotation keys that Potoo
// writes to Kubernetes Events and workload objects. These annotations make outputs
// machine-parseable for AI agents and automation tools.
//
// # Event Annotations
//
// Every Event created by Potoo carries structured annotations
// alongside the human-readable message. Agents can filter and parse these
// without text extraction.
//
// # Workload Annotations
//
// Affected workloads (Deployments, StatefulSets, etc.) are annotated with
// constraint summaries so agents inspecting a workload get constraint context
// immediately without querying a separate CRD.
package annotations

// Event annotation keys.
// These are written to every Event created by Potoo.
const (
	// ManagedBy identifies Events created by Potoo.
	// Value: "potoo"
	// Usage: kubectl get events -l potoo.io/managed-by=potoo
	ManagedBy = "potoo.io/managed-by"

	// EventConstraintType is the constraint category.
	// Value: "NetworkIngress", "NetworkEgress", "Admission", "ResourceLimit", "MeshPolicy", "MissingResource"
	EventConstraintType = "potoo.io/constraint-type"

	// EventConstraintName is the name of the constraint object.
	// Redacted to "redacted" in summary detail level for cross-namespace constraints.
	EventConstraintName = "potoo.io/constraint-name"

	// EventConstraintNamespace is the namespace of the constraint object.
	// Omitted in summary detail level for cross-namespace constraints.
	EventConstraintNamespace = "potoo.io/constraint-namespace"

	// EventSourceGVR is the GroupVersionResource of the source policy object.
	// Value: "networking.k8s.io/v1/networkpolicies"
	EventSourceGVR = "potoo.io/source-gvr"

	// EventSeverity is the severity level.
	// Value: "Critical", "Warning", "Info"
	EventSeverity = "potoo.io/severity"

	// EventEffect is the constraint's effect.
	// Value: "deny", "restrict", "warn", "audit", "limit"
	EventEffect = "potoo.io/effect"

	// EventDetailLevel indicates the privacy scoping applied.
	// Value: "summary", "detailed", "full"
	EventDetailLevel = "potoo.io/detail-level"

	// EventRemediationType is the primary remediation type.
	// Value: "manual", "kubectl", "annotation", "yaml_patch", "link"
	EventRemediationType = "potoo.io/remediation-type"

	// EventRemediationContact is the contact for manual remediation.
	// Value: email or Slack channel
	EventRemediationContact = "potoo.io/remediation-contact"

	// EventStructuredData is a JSON blob containing the full machine-readable
	// constraint data. This is the primary annotation for agent consumption.
	// Agents should prefer parsing this over individual annotations.
	EventStructuredData = "potoo.io/structured-data"
)

// Event label keys.
// Labels enable efficient kubectl filtering (annotations are not filterable).
const (
	// LabelManagedBy enables `kubectl get events -l potoo.io/managed-by=potoo`
	LabelManagedBy = "potoo.io/managed-by"

	// LabelSeverity enables `kubectl get events -l potoo.io/severity=critical`
	// Value is lowercased: "critical", "warning", "info"
	LabelSeverity = "potoo.io/severity"

	// LabelConstraintType enables `kubectl get events -l potoo.io/constraint-type=network-egress`
	// Value is kebab-cased: "network-ingress", "network-egress", "admission", "resource-limit", etc.
	LabelConstraintType = "potoo.io/constraint-type"
)

// Workload annotation keys.
// These are written to Deployments, StatefulSets, etc. that are affected by constraints.
const (
	// WorkloadStatus is a one-line summary of constraints affecting this workload.
	// Value: "3 constraints (1 critical, 2 warning)"
	WorkloadStatus = "potoo.io/status"

	// WorkloadLastEvaluated is the timestamp of the last constraint evaluation.
	// Value: RFC3339 timestamp
	WorkloadLastEvaluated = "potoo.io/last-evaluated"

	// WorkloadConstraints is a JSON array of constraint summaries.
	// Value: [{"type":"NetworkEgress","severity":"Warning","name":"restrict-egress","source":"NetworkPolicy"}]
	// Agents can parse this for immediate constraint context without querying ConstraintReport.
	WorkloadConstraints = "potoo.io/constraints"

	// WorkloadMaxSeverity is the highest severity constraint affecting this workload.
	// Value: "critical", "warning", "info", "none"
	// Enables quick triage: `kubectl get deploy -l potoo.io/max-severity=critical`
	WorkloadMaxSeverity = "potoo.io/max-severity"

	// WorkloadCriticalCount is the number of Critical severity constraints.
	WorkloadCriticalCount = "potoo.io/critical-count"

	// WorkloadWarningCount is the number of Warning severity constraints.
	WorkloadWarningCount = "potoo.io/warning-count"

	// WorkloadInfoCount is the number of Info severity constraints.
	WorkloadInfoCount = "potoo.io/info-count"

	// WorkloadRequires is a YAML-encoded list of companion resources the workload needs.
	// Workload owners declare requirements via this annotation; the annotation-requirements
	// rule evaluates them against the cluster and emits MissingResource constraints.
	// Value: YAML list of {gvr, matching, reason} entries.
	WorkloadRequires = "potoo.io/requires"
)

// Well-known annotation values.
const (
	ManagedByValue = "potoo"
)
