package requirements

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/potooio/potoo/internal/util"
)

// DynamicEvalContext implements types.RequirementEvalContext using a dynamic client.
type DynamicEvalContext struct {
	client dynamic.Interface
}

// NewDynamicEvalContext creates a new DynamicEvalContext.
func NewDynamicEvalContext(client dynamic.Interface) *DynamicEvalContext {
	return &DynamicEvalContext{client: client}
}

// GetNamespace returns the namespace object for the given name.
func (d *DynamicEvalContext) GetNamespace(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	obj, err := d.client.Resource(nsGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get namespace %q: %w", name, err)
	}
	return obj, nil
}

// ListByGVR returns all objects of the given GVR in the given namespace.
// Pass empty namespace for cluster-scoped resources.
func (d *DynamicEvalContext) ListByGVR(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]*unstructured.Unstructured, error) {
	var list *unstructured.UnstructuredList
	var err error

	if namespace == "" {
		list, err = d.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	} else {
		list, err = d.client.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("list %s in %q: %w", gvr.Resource, namespace, err)
	}

	result := make([]*unstructured.Unstructured, len(list.Items))
	for i := range list.Items {
		result[i] = &list.Items[i]
	}
	return result, nil
}

// FindMatchingResources returns resources of the given GVR whose spec.selector
// matches the given workload labels. This follows Kubernetes conventions where
// the resource (e.g., ServiceMonitor) selects workloads via spec.selector.
func (d *DynamicEvalContext) FindMatchingResources(ctx context.Context, gvr schema.GroupVersionResource, namespace string, labels map[string]string) ([]*unstructured.Unstructured, error) {
	all, err := d.ListByGVR(ctx, gvr, namespace)
	if err != nil {
		return nil, err
	}

	var matched []*unstructured.Unstructured
	for _, obj := range all {
		selector := util.SafeNestedLabelSelector(obj.Object, "spec", "selector")
		if selector == nil {
			// No selector means it doesn't target specific workloads; skip.
			continue
		}
		if util.MatchesLabelSelector(selector, labels) {
			matched = append(matched, obj)
		}
	}
	return matched, nil
}
