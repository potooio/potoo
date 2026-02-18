package requirements

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var peerAuthenticationGVR = schema.GroupVersionResource{
	Group: "security.istio.io", Version: "v1", Resource: "peerauthentications",
}

type istioMTLSRule struct{}

// NewIstioMTLSRule returns a rule that checks for PeerAuthentication
// when a namespace has istio-injection enabled.
func NewIstioMTLSRule() types.RequirementRule {
	return &istioMTLSRule{}
}

func (r *istioMTLSRule) Name() string { return "istio-mtls" }

func (r *istioMTLSRule) Description() string {
	return "Checks that namespaces with Istio injection have a PeerAuthentication policy"
}

func (r *istioMTLSRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	namespace := workload.GetNamespace()
	if namespace == "" {
		return nil, nil
	}

	// Get the namespace object and check for istio-injection label.
	nsObj, err := eval.GetNamespace(ctx, namespace)
	if err != nil {
		return nil, err
	}

	nsLabels := nsObj.GetLabels()
	if nsLabels == nil || nsLabels["istio-injection"] != "enabled" {
		return nil, nil
	}

	// Check for PeerAuthentication in the workload's namespace.
	paList, err := eval.ListByGVR(ctx, peerAuthenticationGVR, namespace)
	if err != nil {
		return nil, err
	}
	if len(paList) > 0 {
		return nil, nil
	}

	// Also check for mesh-wide PeerAuthentication in istio-system.
	if namespace != "istio-system" {
		meshPAList, err := eval.ListByGVR(ctx, peerAuthenticationGVR, "istio-system")
		if err == nil && hasMeshWidePA(meshPAList) {
			return nil, nil
		}
		// Non-fatal if istio-system is inaccessible (RBAC, namespace not found).
	}

	name := workload.GetName()
	return []types.Constraint{{
		UID:                k8stypes.UID("missing:istio-mtls:" + namespace + "/" + name),
		Name:               "missing-peer-authentication-" + namespace,
		Namespace:          namespace,
		AffectedNamespaces: []string{namespace},
		ConstraintType:     types.ConstraintTypeMissing,
		Effect:             "missing",
		Severity:           types.SeverityWarning,
		Summary:            "Namespace has Istio injection enabled but no PeerAuthentication policy",
		Details: map[string]interface{}{
			"expectedKind":       "PeerAuthentication",
			"expectedAPIVersion": "security.istio.io/v1",
			"reason":             "Namespace has istio-injection=enabled label but no mTLS policy; using mesh-wide defaults",
		},
		Tags: []string{"istio", "mtls", "security", "missing-resource"},
	}}, nil
}

// hasMeshWidePA checks if any PeerAuthentication in the list is mesh-wide
// (no selector or empty matchLabels, applying to the entire mesh).
func hasMeshWidePA(paList []*unstructured.Unstructured) bool {
	for _, pa := range paList {
		selector := util.SafeNestedMap(pa.Object, "spec", "selector")
		if len(selector) == 0 {
			return true
		}
		// Explicit empty matchLabels means "select all" in Istio.
		matchLabels := util.SafeNestedMap(pa.Object, "spec", "selector", "matchLabels")
		if matchLabels != nil && len(matchLabels) == 0 {
			return true
		}
	}
	return false
}
