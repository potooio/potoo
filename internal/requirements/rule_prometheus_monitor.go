package requirements

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

var (
	serviceMonitorGVR = schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors",
	}
	podMonitorGVR = schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "podmonitors",
	}
)

type prometheusMonitorRule struct{}

// NewPrometheusMonitorRule returns a rule that checks for ServiceMonitor/PodMonitor
// when a workload exposes a metrics port.
func NewPrometheusMonitorRule() types.RequirementRule {
	return &prometheusMonitorRule{}
}

func (r *prometheusMonitorRule) Name() string { return "prometheus-monitor" }

func (r *prometheusMonitorRule) Description() string {
	return "Checks that workloads with a metrics port have a ServiceMonitor or PodMonitor"
}

func (r *prometheusMonitorRule) Evaluate(ctx context.Context, workload *unstructured.Unstructured, eval types.RequirementEvalContext) ([]types.Constraint, error) {
	if !hasMetricsPort(workload) {
		return nil, nil
	}

	name := workload.GetName()
	namespace := workload.GetNamespace()
	if namespace == "" {
		return nil, nil
	}

	// Use pod template labels for matching. ServiceMonitors technically select
	// Services (not pods), but conventionally Service labels mirror pod template
	// labels. PodMonitors select pods directly via these labels.
	podLabels := podTemplateLabels(workload)
	if len(podLabels) == 0 {
		// Fall back to top-level labels if no pod template.
		podLabels = workload.GetLabels()
	}
	if len(podLabels) == 0 {
		return nil, nil
	}

	// Check ServiceMonitors.
	smList, err := eval.FindMatchingResources(ctx, serviceMonitorGVR, namespace, podLabels)
	if err != nil {
		return nil, err
	}
	if len(smList) > 0 {
		return nil, nil
	}

	// Check PodMonitors.
	pmList, err := eval.FindMatchingResources(ctx, podMonitorGVR, namespace, podLabels)
	if err != nil {
		return nil, err
	}
	if len(pmList) > 0 {
		return nil, nil
	}

	return []types.Constraint{{
		UID:                k8stypes.UID("missing:prometheus-monitor:" + namespace + "/" + name),
		Name:               "missing-prometheus-monitor-" + name,
		Namespace:          namespace,
		AffectedNamespaces: []string{namespace},
		ConstraintType:     types.ConstraintTypeMissing,
		Effect:             "missing",
		Severity:           types.SeverityWarning,
		Summary:            "Workload exposes a metrics port but has no ServiceMonitor or PodMonitor",
		Details: map[string]interface{}{
			"expectedKind":       "ServiceMonitor",
			"expectedAPIVersion": "monitoring.coreos.com/v1",
			"reason":             "Workload has a port named metrics or http-metrics but no Prometheus monitor targets it",
		},
		Tags: []string{"prometheus", "monitoring", "missing-resource"},
	}}, nil
}

// hasMetricsPort checks whether any container in the workload's pod template
// has a port named "metrics" or "http-metrics".
func hasMetricsPort(workload *unstructured.Unstructured) bool {
	containers := util.SafeNestedSlice(workload.Object, "spec", "template", "spec", "containers")
	if containers == nil {
		// Bare Pod: containers are at spec.containers.
		containers = util.SafeNestedSlice(workload.Object, "spec", "containers")
	}

	for _, c := range containers {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		ports := util.SafeNestedSlice(cMap, "ports")
		for _, p := range ports {
			pMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			portName := util.SafeStringFromMap(pMap, "name")
			if portName == "metrics" || portName == "http-metrics" {
				return true
			}
		}
	}
	return false
}

// podTemplateLabels extracts labels from spec.template.metadata.labels.
func podTemplateLabels(workload *unstructured.Unstructured) map[string]string {
	raw := util.SafeNestedMap(workload.Object, "spec", "template", "metadata", "labels")
	if raw == nil {
		return nil
	}
	labels := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			labels[k] = s
		}
	}
	return labels
}
