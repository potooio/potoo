package requirements

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
)

var (
	clusterIssuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
	}
	issuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "issuers",
	}
)

type certIssuerRule struct{}

// NewCertIssuerRule returns a rule that checks whether cert-manager Issuers
// referenced by workload annotations actually exist.
func NewCertIssuerRule() types.RequirementRule {
	return &certIssuerRule{}
}

func (r *certIssuerRule) Name() string { return "cert-issuer" }

func (r *certIssuerRule) Description() string {
	return "Checks that cert-manager Issuers referenced by workload annotations exist"
}

func (r *certIssuerRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	annotations := workload.GetAnnotations()
	if annotations == nil {
		return nil, nil
	}

	name := workload.GetName()
	namespace := workload.GetNamespace()

	// Check for cluster-issuer annotation (takes precedence over namespaced issuer).
	if clusterIssuerName, ok := annotations["cert-manager.io/cluster-issuer"]; ok && clusterIssuerName != "" {
		exists, err := issuerExists(ctx, eval, clusterIssuerGVR, "", clusterIssuerName)
		if err != nil {
			return nil, err
		}
		if !exists {
			return []types.Constraint{makeCertConstraint(name, namespace, "ClusterIssuer", clusterIssuerName)}, nil
		}
		// ClusterIssuer exists — cert-manager only uses one issuer annotation,
		// so skip the namespaced issuer check.
		return nil, nil
	}

	// Check for namespaced issuer annotation.
	if issuerName, ok := annotations["cert-manager.io/issuer-name"]; ok && issuerName != "" {
		if namespace == "" {
			return nil, nil
		}
		exists, err := issuerExists(ctx, eval, issuerGVR, namespace, issuerName)
		if err != nil {
			return nil, err
		}
		if !exists {
			return []types.Constraint{makeCertConstraint(name, namespace, "Issuer", issuerName)}, nil
		}
	}

	return nil, nil
}

// issuerExists checks if an issuer with the given name exists.
func issuerExists(ctx context.Context, eval types.RequirementEvalContext, gvr schema.GroupVersionResource, namespace, issuerName string) (bool, error) {
	list, err := eval.ListByGVR(ctx, gvr, namespace)
	if err != nil {
		return false, err
	}
	for _, obj := range list {
		if obj.GetName() == issuerName {
			return true, nil
		}
	}
	return false, nil
}

func makeCertConstraint(workloadName, namespace, issuerKind, issuerName string) types.Constraint {
	ns := namespace
	if ns == "" {
		ns = "cluster"
	}
	return types.Constraint{
		UID:                k8stypes.UID("missing:cert-issuer:" + ns + "/" + workloadName + ":" + strings.ToLower(issuerKind) + "/" + issuerName),
		Name:               "missing-" + strings.ToLower(issuerKind) + "-" + issuerName,
		Namespace:          namespace,
		AffectedNamespaces: []string{namespace},
		ConstraintType:     types.ConstraintTypeMissing,
		Effect:             "missing",
		Severity:           types.SeverityCritical,
		Summary:            issuerKind + " " + issuerName + " referenced by workload does not exist",
		Details: map[string]interface{}{
			"expectedKind":       issuerKind,
			"expectedAPIVersion": "cert-manager.io/v1",
			"reason":             "Workload annotation references " + issuerKind + " " + issuerName + " which does not exist",
			"issuerName":         issuerName,
		},
		Tags: []string{"cert-manager", "tls", "missing-resource"},
	}
}
