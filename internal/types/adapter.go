package types

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Adapter parses a specific type of Kubernetes resource into normalized Constraints.
//
// Each adapter handles one or more GVRs (GroupVersionResources). The discovery
// engine routes unstructured objects to the appropriate adapter based on GVR matching.
//
// Implementations must be safe for concurrent use.
type Adapter interface {
	// Name returns a unique identifier for this adapter.
	// Used in metrics labels, logging, and ConstraintProfile references.
	// Examples: "cilium-network-policy", "gatekeeper", "networkpolicy"
	Name() string

	// Handles returns the GVRs this adapter can parse.
	// The discovery engine calls this at startup and on periodic re-scan.
	// Return a wildcard resource ("*") to handle all resources in a group.
	Handles() []schema.GroupVersionResource

	// Parse converts an unstructured Kubernetes object into zero or more
	// normalized Constraint models.
	//
	// Returns multiple constraints when a single policy object contains
	// multiple independent rules (e.g., a Kyverno ClusterPolicy with N rules,
	// or a CiliumNetworkPolicy with separate ingress and egress sections).
	//
	// Contract:
	//   - Must not modify the input object.
	//   - Must not panic; return errors instead.
	//   - Should populate Summary with a human-readable description.
	//   - Should populate AffectedNamespaces/WorkloadSelector when determinable.
	//   - May leave RawObject nil if the indexer should not store it (memory optimization).
	Parse(ctx context.Context, obj *unstructured.Unstructured) ([]Constraint, error)
}

// RequirementRule evaluates whether a workload is missing a required companion resource.
//
// Unlike Adapters (which parse existing constraint objects), RequirementRules
// reason about the *absence* of expected resources.
type RequirementRule interface {
	// Name returns a unique identifier for this rule.
	Name() string

	// Description returns a human-readable explanation of what this rule checks.
	Description() string

	// Evaluate checks whether the given workload is missing a required resource.
	// Returns zero or more Constraints of type ConstraintTypeMissing.
	//
	// The evaluator provides helper methods to query the cluster for related resources.
	Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval RequirementEvalContext) ([]Constraint, error)
}

// RequirementEvalContext provides helpers for RequirementRules to query cluster state.
type RequirementEvalContext interface {
	// GetNamespace returns the namespace object for the given name.
	GetNamespace(ctx context.Context, name string) (*unstructured.Unstructured, error)

	// ListByGVR returns all objects of the given GVR in the given namespace.
	// Pass empty namespace for cluster-scoped resources.
	ListByGVR(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]*unstructured.Unstructured, error)

	// FindMatchingResources returns resources of the given GVR whose label selector
	// matches the given labels.
	FindMatchingResources(ctx context.Context, gvr schema.GroupVersionResource, namespace string, labels map[string]string) ([]*unstructured.Unstructured, error)
}
