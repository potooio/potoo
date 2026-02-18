package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=cr
// +kubebuilder:printcolumn:name="Constraints",type=integer,JSONPath=`.status.constraintCount`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.criticalCount`
// +kubebuilder:printcolumn:name="Warning",type=integer,JSONPath=`.status.warningCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ConstraintReport is a per-namespace summary of all constraints affecting
// workloads in that namespace. Created and updated automatically by the controller.
type ConstraintReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status ConstraintReportStatus `json:"status,omitempty"`
}

type ConstraintReportStatus struct {
	// Total number of constraints affecting this namespace.
	ConstraintCount int `json:"constraintCount"`

	// Count by severity.
	CriticalCount int `json:"criticalCount"`
	WarningCount  int `json:"warningCount"`
	InfoCount     int `json:"infoCount"`

	// Individual constraint entries (human-readable, for kubectl display).
	Constraints []ConstraintEntry `json:"constraints,omitempty"`

	// MachineReadable contains structured data optimized for programmatic consumption
	// by AI agents, kubectl plugins, and automation tools. This section contains the
	// same data as Constraints but in a richer, typed format with structured remediation.
	MachineReadable *MachineReadableReport `json:"machineReadable,omitempty"`

	// LastUpdated is when this report was last reconciled.
	LastUpdated metav1.Time `json:"lastUpdated"`
}

type ConstraintEntry struct {
	// Name of the constraint (redacted if cross-namespace, per privacy model).
	Name string `json:"name"`

	// Type of constraint.
	// +kubebuilder:validation:Enum=NetworkIngress;NetworkEgress;Admission;ResourceLimit;MeshPolicy;MissingResource;Unknown
	Type string `json:"type"`

	// Severity level.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	Severity string `json:"severity"`

	// AffectedWorkloads lists the workload names in this namespace that match.
	AffectedWorkloads []string `json:"affectedWorkloads,omitempty"`

	// Message is a human-readable summary (detail level depends on privacy scope).
	Message string `json:"message"`

	// Source identifies the type of policy engine that created this constraint.
	Source string `json:"source"`

	// LastSeen is when this constraint was last observed.
	LastSeen metav1.Time `json:"lastSeen"`
}

// ---
// Machine-readable types for agent consumption.
// See docs/AGENT_OUTPUTS.md for design rationale.
// ---

// MachineReadableReport is the structured, agent-optimized section of a ConstraintReport.
type MachineReadableReport struct {
	// SchemaVersion allows agents to detect breaking changes. Currently "1".
	SchemaVersion string `json:"schemaVersion"`

	// GeneratedAt is when this machine-readable section was last rendered.
	GeneratedAt metav1.Time `json:"generatedAt"`

	// DetailLevel indicates the privacy scoping applied to this report.
	// +kubebuilder:validation:Enum=summary;detailed;full
	DetailLevel string `json:"detailLevel"`

	// Constraints is the structured list of active constraints.
	Constraints []MachineConstraintEntry `json:"constraints,omitempty"`

	// MissingResources lists detected missing companion resources.
	MissingResources []MissingResourceEntry `json:"missingResources,omitempty"`

	// Tags is a flat list of all tags across all constraints for agent filtering.
	Tags []string `json:"tags,omitempty"`
}

// MachineConstraintEntry is a single constraint in the machine-readable report.
type MachineConstraintEntry struct {
	// UID of the constraint (stable across report regenerations).
	UID string `json:"uid"`

	// Name of the constraint.
	Name string `json:"name"`

	// ConstraintType categorizes the constraint.
	// +kubebuilder:validation:Enum=NetworkIngress;NetworkEgress;Admission;ResourceLimit;MeshPolicy;MissingResource;Unknown
	ConstraintType string `json:"constraintType"`

	// Severity level.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	Severity string `json:"severity"`

	// Effect is what this constraint does (deny, restrict, warn, limit, audit).
	Effect string `json:"effect"`

	// SourceRef identifies the Kubernetes object that defines this constraint.
	// Agents can use this to fetch the full policy (subject to RBAC).
	SourceRef ObjectReference `json:"sourceRef"`

	// AffectedWorkloads lists workloads in this namespace matched by this constraint.
	AffectedWorkloads []WorkloadReference `json:"affectedWorkloads,omitempty"`

	// Remediation provides structured, actionable remediation steps.
	Remediation RemediationInfo `json:"remediation"`

	// Metrics contains quantitative data (e.g., quota utilization percentages).
	// Only populated for ResourceLimit constraints.
	// +optional
	Metrics map[string]ResourceMetric `json:"metrics,omitempty"`

	// Tags for agent filtering (e.g., "network", "egress", "port-restriction").
	Tags []string `json:"tags,omitempty"`

	// LastObserved is when this constraint was last seen in the cluster.
	LastObserved metav1.Time `json:"lastObserved"`
}

// ObjectReference identifies a Kubernetes object without requiring typed imports.
type ObjectReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	// Namespace is empty for cluster-scoped objects.
	Namespace string `json:"namespace,omitempty"`
}

// WorkloadReference identifies an affected workload with the reason it matched.
type WorkloadReference struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	MatchReason string `json:"matchReason,omitempty"`
}

// RemediationInfo contains structured remediation data.
type RemediationInfo struct {
	// Summary is a one-line human-readable description.
	Summary string `json:"summary"`

	// Steps is an ordered list of remediation actions.
	Steps []RemediationStep `json:"steps,omitempty"`
}

// RemediationStep is a single actionable remediation step.
type RemediationStep struct {
	// Type categorizes this step.
	// +kubebuilder:validation:Enum=manual;kubectl;annotation;yaml_patch;link
	Type string `json:"type"`

	// Description is a human-readable explanation of this step.
	Description string `json:"description"`

	// Command is a kubectl command to run (populated when Type=kubectl).
	// +optional
	Command string `json:"command,omitempty"`

	// Patch is a kubectl patch command (populated when Type=annotation or yaml_patch).
	// +optional
	Patch string `json:"patch,omitempty"`

	// Template is a YAML manifest template (populated when Type=yaml_patch).
	// May contain {workload_name}, {namespace} placeholders.
	// +optional
	Template string `json:"template,omitempty"`

	// URL is a link to documentation or a runbook (populated when Type=link).
	// +optional
	URL string `json:"url,omitempty"`

	// Contact is a contact address for manual steps (email, Slack channel).
	// +optional
	Contact string `json:"contact,omitempty"`

	// RequiresPrivilege indicates the minimum privilege level needed.
	// +kubebuilder:validation:Enum=developer;namespace-admin;cluster-admin
	RequiresPrivilege string `json:"requiresPrivilege,omitempty"`
}

// ResourceMetric holds quantitative data for a single resource type.
type ResourceMetric struct {
	Hard        string  `json:"hard"`
	Used        string  `json:"used"`
	Unit        string  `json:"unit"`
	PercentUsed float64 `json:"percentUsed"`
}

// MissingResourceEntry describes a companion resource that should exist but doesn't.
type MissingResourceEntry struct {
	// ExpectedKind is the Kubernetes kind that should exist.
	ExpectedKind string `json:"expectedKind"`

	// ExpectedAPIVersion is the API version of the expected resource.
	ExpectedAPIVersion string `json:"expectedAPIVersion"`

	// Reason explains why this resource is expected.
	Reason string `json:"reason"`

	// Severity level.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	Severity string `json:"severity"`

	// ForWorkload identifies which workload needs this resource.
	ForWorkload WorkloadReference `json:"forWorkload"`

	// Remediation provides steps to create the missing resource.
	Remediation RemediationInfo `json:"remediation"`
}

// +kubebuilder:object:root=true
type ConstraintReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstraintReport `json:"items"`
}

// ---

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=cp

// ConstraintProfile configures how a specific CRD type is treated by the
// discovery engine. Platform admins use this to register custom policy CRDs
// or tune adapter behavior.
type ConstraintProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ConstraintProfileSpec `json:"spec"`
}

type ConstraintProfileSpec struct {
	// GVR identifies the target resource type.
	GVR GVRReference `json:"gvr"`

	// Adapter is the name of the adapter to use for parsing.
	// Use "generic" for unknown CRDs or the name of a built-in adapter.
	Adapter string `json:"adapter"`

	// Enabled controls whether this resource type is watched.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// Severity overrides the default severity for constraints from this source.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	// +optional
	Severity string `json:"severity,omitempty"`

	// DebounceSeconds overrides the default debounce interval for notifications.
	// +optional
	DebounceSeconds *int `json:"debounceSeconds,omitempty"`

	// FieldPaths configures custom extraction paths for the generic adapter.
	// Only used when Adapter is "generic". Each path is dot-delimited
	// (e.g., "spec.workloadSelector").
	// +optional
	FieldPaths *FieldPaths `json:"fieldPaths,omitempty"`
}

// FieldPaths configures how the generic adapter extracts constraint data from
// arbitrary CRDs. Each field is a dot-delimited path into the object's structure.
type FieldPaths struct {
	// SelectorPath is the path to the workload label selector.
	// Example: "spec.workloadSelector"
	// +optional
	SelectorPath string `json:"selectorPath,omitempty"`

	// NamespaceSelectorPath is the path to the namespace label selector.
	// Example: "spec.namespaceSelector"
	// +optional
	NamespaceSelectorPath string `json:"namespaceSelectorPath,omitempty"`

	// EffectPath is the path to the effect/action field.
	// Example: "spec.action"
	// +optional
	EffectPath string `json:"effectPath,omitempty"`

	// SummaryPath is the path to a human-readable description.
	// Example: "spec.description"
	// +optional
	SummaryPath string `json:"summaryPath,omitempty"`
}

type GVRReference struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// +kubebuilder:object:root=true
type ConstraintProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConstraintProfile `json:"items"`
}

// ---

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=np

// NotificationPolicy configures how notifications are delivered and what
// detail level is visible to each audience.
type NotificationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NotificationPolicySpec `json:"spec"`
}

type NotificationPolicySpec struct {
	// DeveloperScope controls what developers see in their own namespace.
	DeveloperScope NotificationScope `json:"developerScope"`

	// PlatformAdminScope controls what platform admins see.
	PlatformAdminScope NotificationScope `json:"platformAdminScope"`

	// PlatformAdminRoles identifies which ClusterRoles are considered platform admin.
	PlatformAdminRoles []string `json:"platformAdminRoles,omitempty"`

	// Channels configures external notification delivery.
	Channels NotificationChannels `json:"channels,omitempty"`
}

type NotificationScope struct {
	// ShowConstraintType includes the constraint type in notifications.
	ShowConstraintType bool `json:"showConstraintType"`

	// ShowConstraintName controls constraint name visibility.
	// "same-namespace-only" = only show name if constraint is in the recipient's namespace.
	// "all" = show all constraint names.
	// "none" = never show constraint names.
	// +kubebuilder:validation:Enum=none;same-namespace-only;all
	ShowConstraintName string `json:"showConstraintName"`

	// ShowAffectedPorts includes specific port numbers in notifications.
	ShowAffectedPorts bool `json:"showAffectedPorts"`

	// ShowRemediationContact includes contact information in notifications.
	ShowRemediationContact bool `json:"showRemediationContact"`

	// Contact is the default contact for remediation (e.g., email, Slack channel).
	Contact string `json:"contact,omitempty"`

	// MaxDetailLevel caps the detail level for this scope.
	// +kubebuilder:validation:Enum=summary;detailed;full
	MaxDetailLevel string `json:"maxDetailLevel"`
}

type NotificationChannels struct {
	// Slack configuration for external notifications.
	Slack *SlackConfig `json:"slack,omitempty"`

	// Webhook configuration for generic HTTP POST notifications.
	Webhook *WebhookConfig `json:"webhook,omitempty"`
}

type SlackConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhookUrl"`
	// MinSeverity is the minimum severity to trigger Slack notifications.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	MinSeverity string `json:"minSeverity,omitempty"`
}

type WebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`

	// TimeoutSeconds is the HTTP request timeout. Default: 10.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// MinSeverity is the minimum severity to trigger webhook notifications.
	// +kubebuilder:validation:Enum=Critical;Warning;Info
	MinSeverity string `json:"minSeverity,omitempty"`

	// AuthSecretRef references a Secret containing an auth token for webhook requests.
	// The Secret value is sent as a Bearer token in the Authorization header.
	AuthSecretRef *SecretKeyReference `json:"authSecretRef,omitempty"`
}

// SecretKeyReference identifies a key within a Kubernetes Secret.
type SecretKeyReference struct {
	// Name is the name of the Secret.
	Name string `json:"name"`
	// Key is the key within the Secret data.
	Key string `json:"key"`
}

// +kubebuilder:object:root=true
type NotificationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NotificationPolicy `json:"items"`
}
