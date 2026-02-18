package requirements

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var (
	virtualServiceGVR = schema.GroupVersionResource{
		Group: "networking.istio.io", Version: "v1", Resource: "virtualservices",
	}
	destinationRuleGVR = schema.GroupVersionResource{
		Group: "networking.istio.io", Version: "v1", Resource: "destinationrules",
	}
)

type istioRoutingRule struct{}

// NewIstioRoutingRule returns a rule that checks for VirtualService/DestinationRule
// when a workload has the Istio sidecar annotation.
func NewIstioRoutingRule() types.RequirementRule {
	return &istioRoutingRule{}
}

func (r *istioRoutingRule) Name() string { return "istio-routing" }

func (r *istioRoutingRule) Description() string {
	return "Checks that workloads with Istio sidecar have a VirtualService or DestinationRule"
}

func (r *istioRoutingRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	annotations := workload.GetAnnotations()
	if annotations == nil {
		return nil, nil
	}
	if _, ok := annotations["sidecar.istio.io/status"]; !ok {
		return nil, nil
	}

	name := workload.GetName()
	namespace := workload.GetNamespace()
	if namespace == "" {
		return nil, nil
	}

	// Check for VirtualServices that route to this workload.
	// NOTE: Istio VirtualService hosts reference Services, not workloads directly.
	// This assumes the workload name matches its Service name (conventional pattern).
	vsList, err := eval.ListByGVR(ctx, virtualServiceGVR, namespace)
	if err != nil {
		return nil, err
	}
	if vsMatchesWorkload(vsList, name, namespace) {
		return nil, nil
	}

	// Check for DestinationRules that target this workload.
	drList, err := eval.ListByGVR(ctx, destinationRuleGVR, namespace)
	if err != nil {
		return nil, err
	}
	if drMatchesWorkload(drList, name, namespace) {
		return nil, nil
	}

	return []types.Constraint{{
		UID:                k8stypes.UID("missing:istio-routing:" + namespace + "/" + name),
		Name:               "missing-istio-routing-" + name,
		Namespace:          namespace,
		AffectedNamespaces: []string{namespace},
		ConstraintType:     types.ConstraintTypeMissing,
		Effect:             "missing",
		Severity:           types.SeverityWarning,
		Summary:            "Workload has Istio sidecar but no VirtualService or DestinationRule",
		Details: map[string]interface{}{
			"expectedKind":       "VirtualService",
			"expectedAPIVersion": "networking.istio.io/v1",
			"reason":             "Workload has sidecar.istio.io/status annotation but no routing rules",
		},
		Tags: []string{"istio", "routing", "missing-resource"},
	}}, nil
}

// vsMatchesWorkload checks if any VirtualService routes to the given workload.
func vsMatchesWorkload(vsList []*unstructured.Unstructured, workloadName, namespace string) bool {
	for _, vs := range vsList {
		if vsRoutesToHost(vs, workloadName, namespace) {
			return true
		}
	}
	return false
}

// vsRoutesToHost checks whether a VirtualService has any route destination
// that matches the workload name (short, namespaced, or FQDN form).
func vsRoutesToHost(vs *unstructured.Unstructured, workloadName, namespace string) bool {
	httpRoutes := util.SafeNestedSlice(vs.Object, "spec", "http")
	for _, httpRoute := range httpRoutes {
		routeMap, ok := httpRoute.(map[string]interface{})
		if !ok {
			continue
		}
		routes := util.SafeNestedSlice(routeMap, "route")
		for _, route := range routes {
			rm, ok := route.(map[string]interface{})
			if !ok {
				continue
			}
			host := util.SafeNestedString(rm, "destination", "host")
			if hostMatchesWorkload(host, workloadName, namespace) {
				return true
			}
		}
	}

	// Also check tcp and tls routes.
	for _, routeType := range []string{"tcp", "tls"} {
		tcpRoutes := util.SafeNestedSlice(vs.Object, "spec", routeType)
		for _, tcpRoute := range tcpRoutes {
			routeMap, ok := tcpRoute.(map[string]interface{})
			if !ok {
				continue
			}
			routes := util.SafeNestedSlice(routeMap, "route")
			for _, route := range routes {
				rm, ok := route.(map[string]interface{})
				if !ok {
					continue
				}
				host := util.SafeNestedString(rm, "destination", "host")
				if hostMatchesWorkload(host, workloadName, namespace) {
					return true
				}
			}
		}
	}
	return false
}

// hostMatchesWorkload checks if an Istio host string matches a workload name.
// Accepts: "name", "name.namespace", "name.namespace.svc.cluster.local".
func hostMatchesWorkload(host, workloadName, namespace string) bool {
	if host == "" {
		return false
	}
	host = strings.TrimSpace(host)

	if host == workloadName {
		return true
	}
	if host == workloadName+"."+namespace {
		return true
	}
	if host == workloadName+"."+namespace+".svc.cluster.local" {
		return true
	}
	return false
}

// drMatchesWorkload checks if any DestinationRule targets the given workload.
func drMatchesWorkload(drList []*unstructured.Unstructured, workloadName, namespace string) bool {
	for _, dr := range drList {
		host := util.SafeNestedString(dr.Object, "spec", "host")
		if hostMatchesWorkload(host, workloadName, namespace) {
			return true
		}
	}
	return false
}
