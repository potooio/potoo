package requirements

import (
	"context"
	"errors"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
)

// crdCheck defines a single CRD-existence check: a trigger condition on the workload
// and the GVR whose CRD must be installed.
type crdCheck struct {
	// triggerFn returns true if the workload requires this CRD.
	triggerFn func(workload *unstructured.Unstructured) bool
	// gvr is the GroupVersionResource whose CRD should be installed.
	gvr schema.GroupVersionResource
	// crdName is the fully-qualified CRD name (e.g., "servicemonitors.monitoring.coreos.com").
	crdName string
	// reason explains why this CRD is expected.
	reason string
}

type crdInstalledRule struct {
	checks []crdCheck
}

// NewCRDInstalledRule returns a rule that detects when a workload references
// functionality from a CRD that is not installed in the cluster.
func NewCRDInstalledRule() types.RequirementRule {
	return &crdInstalledRule{
		checks: []crdCheck{
			{
				triggerFn: hasMetricsPort,
				gvr:       serviceMonitorGVR,
				crdName:   "servicemonitors.monitoring.coreos.com",
				reason:    "Workload exposes a metrics port but the CRD servicemonitors.monitoring.coreos.com is not installed",
			},
			{
				triggerFn: hasIstioInjectionAnnotation,
				gvr:       peerAuthenticationGVR,
				crdName:   "peerauthentications.security.istio.io",
				reason:    "Workload has Istio sidecar injection but the CRD peerauthentications.security.istio.io is not installed",
			},
			{
				triggerFn: hasCertManagerAnnotation,
				gvr:       clusterIssuerGVR,
				crdName:   "clusterissuers.cert-manager.io",
				reason:    "Workload references a cert-manager issuer but the CRD clusterissuers.cert-manager.io is not installed",
			},
		},
	}
}

func (r *crdInstalledRule) Name() string { return "crd-installed" }

func (r *crdInstalledRule) Description() string {
	return "Checks that CRDs referenced by workload annotations or ports are installed in the cluster"
}

func (r *crdInstalledRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	name := workload.GetName()
	namespace := workload.GetNamespace()
	if namespace == "" {
		return nil, nil
	}

	var constraints []types.Constraint
	for _, check := range r.checks {
		if !check.triggerFn(workload) {
			continue
		}

		// Probe the GVR with a namespace-scoped list. If the CRD is not installed,
		// the API server returns a 404 NotFound error.
		_, err := eval.ListByGVR(ctx, check.gvr, namespace)
		if err == nil {
			// CRD is installed (list succeeded); skip.
			continue
		}

		// Only treat 404 (resource not found) as "CRD not installed".
		// Other errors (RBAC, network) are silently skipped to avoid
		// false positives and to allow remaining checks to proceed.
		if !isResourceNotFoundError(err) {
			continue
		}

		constraints = append(constraints, types.Constraint{
			UID:                k8stypes.UID("missing:crd:" + namespace + "/" + name + ":" + check.crdName),
			Name:               "missing-crd-" + crdShortName(check.crdName),
			Namespace:          namespace,
			AffectedNamespaces: []string{namespace},
			ConstraintType:     types.ConstraintTypeMissing,
			Effect:             "missing",
			Severity:           types.SeverityWarning,
			Summary:            "CRD " + check.crdName + " is not installed",
			Details: map[string]interface{}{
				"expectedCRD": check.crdName,
				"reason":      check.reason,
			},
			Tags: []string{"missing-crd", "missing-resource"},
		})
	}

	return constraints, nil
}

// hasIstioInjectionAnnotation returns true if the workload has a sidecar.istio.io/status annotation.
func hasIstioInjectionAnnotation(workload *unstructured.Unstructured) bool {
	annotations := workload.GetAnnotations()
	if annotations == nil {
		return false
	}
	_, ok := annotations["sidecar.istio.io/status"]
	return ok
}

// hasCertManagerAnnotation returns true if the workload references a cert-manager issuer.
func hasCertManagerAnnotation(workload *unstructured.Unstructured) bool {
	annotations := workload.GetAnnotations()
	if annotations == nil {
		return false
	}
	if v, ok := annotations["cert-manager.io/cluster-issuer"]; ok && v != "" {
		return true
	}
	if v, ok := annotations["cert-manager.io/issuer-name"]; ok && v != "" {
		return true
	}
	return false
}

// isResourceNotFoundError checks if the error indicates the API resource type
// is not registered (CRD not installed), as opposed to a specific object not found.
func isResourceNotFoundError(err error) bool {
	// Use errors.As to unwrap wrapped errors from the dynamic client.
	var statusErr *apierrors.StatusError
	if errors.As(err, &statusErr) {
		if apierrors.IsNotFound(statusErr) {
			return true
		}
	}
	// Fallback: check for common error message patterns when the error
	// is not a standard StatusError (e.g., discovery failures).
	msg := err.Error()
	return strings.Contains(msg, "the server could not find the requested resource") ||
		strings.Contains(msg, "no matches for kind")
}

// crdShortName extracts a short name from a fully-qualified CRD name.
// "servicemonitors.monitoring.coreos.com" -> "servicemonitors"
func crdShortName(crdName string) string {
	parts := strings.SplitN(crdName, ".", 2)
	return parts[0]
}
