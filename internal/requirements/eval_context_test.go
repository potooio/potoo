package requirements

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newFakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClient(scheme, objects...)
}

func TestDynamicEvalContext_GetNamespace(t *testing.T) {
	ns := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]interface{}{
				"name": "my-ns",
				"labels": map[string]interface{}{
					"istio-injection": "enabled",
				},
			},
		},
	}

	client := newFakeClient(ns)
	evalCtx := NewDynamicEvalContext(client)

	got, err := evalCtx.GetNamespace(context.Background(), "my-ns")
	if err != nil {
		t.Fatal(err)
	}
	if got.GetName() != "my-ns" {
		t.Fatalf("expected my-ns, got %s", got.GetName())
	}
	labels := got.GetLabels()
	if labels["istio-injection"] != "enabled" {
		t.Fatal("expected istio-injection=enabled label")
	}
}

func TestDynamicEvalContext_GetNamespace_NotFound(t *testing.T) {
	client := newFakeClient()
	evalCtx := NewDynamicEvalContext(client)

	_, err := evalCtx.GetNamespace(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent namespace")
	}
}

func TestDynamicEvalContext_ListByGVR(t *testing.T) {
	sm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata": map[string]interface{}{
				"name":      "my-sm",
				"namespace": "default",
			},
		},
	}

	client := newFakeClient(sm)
	evalCtx := NewDynamicEvalContext(client)

	gvr := schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors",
	}

	results, err := evalCtx.ListByGVR(context.Background(), gvr, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].GetName() != "my-sm" {
		t.Fatalf("expected my-sm, got %s", results[0].GetName())
	}
}

func TestDynamicEvalContext_ListByGVR_ClusterScoped(t *testing.T) {
	ci := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "ClusterIssuer",
			"metadata": map[string]interface{}{
				"name": "letsencrypt",
			},
		},
	}

	client := newFakeClient(ci)
	evalCtx := NewDynamicEvalContext(client)

	gvr := schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
	}

	results, err := evalCtx.ListByGVR(context.Background(), gvr, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestDynamicEvalContext_FindMatchingResources(t *testing.T) {
	sm1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata":   map[string]interface{}{"name": "matches", "namespace": "default"},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "my-app"},
				},
			},
		},
	}
	sm2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata":   map[string]interface{}{"name": "no-match", "namespace": "default"},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "other-app"},
				},
			},
		},
	}

	client := newFakeClient(sm1, sm2)
	evalCtx := NewDynamicEvalContext(client)

	gvr := schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors",
	}

	results, err := evalCtx.FindMatchingResources(context.Background(), gvr, "default", map[string]string{"app": "my-app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].GetName() != "matches" {
		t.Fatalf("expected 'matches', got %s", results[0].GetName())
	}
}

func TestDynamicEvalContext_FindMatchingResources_NoSelector(t *testing.T) {
	sm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata":   map[string]interface{}{"name": "no-selector", "namespace": "default"},
			"spec":       map[string]interface{}{},
		},
	}

	client := newFakeClient(sm)
	evalCtx := NewDynamicEvalContext(client)

	gvr := schema.GroupVersionResource{
		Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors",
	}

	results, err := evalCtx.FindMatchingResources(context.Background(), gvr, "default", map[string]string{"app": "my-app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 matches for resource without selector, got %d", len(results))
	}
}
