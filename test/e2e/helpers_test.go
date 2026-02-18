//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/potooio/potoo/internal/annotations"
)

const (
	// testNamespacePrefix is the prefix for test namespace names.
	testNamespacePrefix = "potoo-e2e-"

	// e2eLabel marks resources created by E2E tests for cleanup.
	e2eLabel = "potoo-e2e"

	// controllerNamespace is the namespace where the controller is deployed.
	controllerNamespace = "potoo-system"

	// controllerDeploymentName is the name of the controller deployment.
	controllerDeploymentName = "potoo-controller"

	// defaultPollInterval is the default interval for polling loops.
	defaultPollInterval = 1 * time.Second

	// defaultTimeout is the default timeout for wait operations.
	defaultTimeout = 60 * time.Second
)

// markFlaky marks a test as known-flaky due to timing sensitivity in the
// e2e environment. When E2E_SKIP_FLAKY=1 is set, the test is skipped.
// Without that env var, flaky tests run normally — they stay in the suite
// to catch real regressions.
//
// In CI, use `make test-e2e-retry` which retries flaky failures once before
// failing, or set E2E_SKIP_FLAKY=1 to skip them entirely.
//
// Usage: call at the start of any flaky subtest:
//
//	t.Run("Deduplication", func(t *testing.T) {
//	    markFlaky(t, "timing-sensitive dedup saturation with parallel cluster-scoped constraints")
//	    ...
//	})
func markFlaky(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("E2E_SKIP_FLAKY") == "1" {
		t.Skipf("SKIPPED (flaky): %s", reason)
	}
	t.Logf("FLAKY TEST: %s — set E2E_SKIP_FLAKY=1 to skip", reason)
}

// waitForCondition polls until conditionFn returns true or the timeout expires.
func waitForCondition(t *testing.T, timeout, interval time.Duration, conditionFn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := conditionFn()
		if err != nil {
			t.Logf("waitForCondition: %v", err)
		}
		if ok {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("waitForCondition: timed out after %v", timeout)
}

// waitForControllerReady waits for the controller deployment to have at least
// one ready replica by checking the deployment status via the Kubernetes API.
func waitForControllerReady(t *testing.T, clientset kubernetes.Interface, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for controller deployment %s/%s to become ready...", controllerNamespace, controllerDeploymentName)

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		deploy, err := clientset.AppsV1().Deployments(controllerNamespace).Get(
			context.Background(), controllerDeploymentName, metav1.GetOptions{},
		)
		if err != nil {
			return false, fmt.Errorf("get deployment: %w", err)
		}
		if deploy.Status.ReadyReplicas > 0 {
			var desired int32 = 1
			if deploy.Spec.Replicas != nil {
				desired = *deploy.Spec.Replicas
			}
			t.Logf("Controller ready: %d/%d replicas", deploy.Status.ReadyReplicas, desired)
			return true, nil
		}
		return false, nil
	})
}

// waitForDeploymentReady waits for a deployment to have all replicas ready.
func waitForDeploymentReady(t *testing.T, clientset kubernetes.Interface, namespace, name string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for deployment %s/%s to become ready...", namespace, name)

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		deploy, err := clientset.AppsV1().Deployments(namespace).Get(
			context.Background(), name, metav1.GetOptions{},
		)
		if err != nil {
			return false, fmt.Errorf("get deployment: %w", err)
		}
		if deploy.Spec.Replicas != nil && deploy.Status.ReadyReplicas >= *deploy.Spec.Replicas {
			return true, nil
		}
		return false, nil
	})
}

// createTestNamespace creates a labeled namespace with a random suffix.
// Returns the namespace name and a cleanup function that deletes it.
func createTestNamespace(t *testing.T, clientset kubernetes.Interface) (string, func()) {
	t.Helper()
	name := testNamespacePrefix + rand.String(6)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				e2eLabel: "true",
			},
		},
	}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create test namespace %s", name)
	t.Logf("Created test namespace: %s", name)

	cleanup := func() {
		t.Logf("Deleting test namespace: %s", name)
		err := clientset.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil {
			t.Logf("Warning: failed to delete namespace %s: %v", name, err)
		}
	}
	return name, cleanup
}

// waitForEvent polls for Kubernetes Events in the given namespace that reference
// the specified involved object name. Returns the matching events.
func waitForEvent(t *testing.T, clientset kubernetes.Interface, namespace, involvedObjectName string, timeout time.Duration) []corev1.Event {
	t.Helper()
	var matched []corev1.Event

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		events, err := clientset.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("list events: %w", err)
		}
		matched = nil
		for _, ev := range events.Items {
			if ev.InvolvedObject.Name == involvedObjectName {
				matched = append(matched, ev)
			}
		}
		return len(matched) > 0, nil
	})
	return matched
}

// assertEventExists asserts that at least one Kubernetes Event exists in the
// namespace for the given workload that carries the expected Potoo annotations.
// expectedAnnotations is a map of annotation key to expected value.
func assertEventExists(t *testing.T, clientset kubernetes.Interface, namespace, workloadName string, expectedAnnotations map[string]string, timeout time.Duration) {
	t.Helper()
	events := waitForEvent(t, clientset, namespace, workloadName, timeout)
	require.NotEmpty(t, events, "no events found for workload %s/%s", namespace, workloadName)

	// Find at least one event matching all expected annotations.
	for _, ev := range events {
		if ev.Annotations == nil {
			continue
		}
		allMatch := true
		for k, v := range expectedAnnotations {
			if ev.Annotations[k] != v {
				allMatch = false
				break
			}
		}
		if allMatch {
			t.Logf("Found matching event: %s (reason=%s)", ev.Name, ev.Reason)
			return
		}
	}

	// No event matched all annotations — report what we found.
	t.Errorf("No event on %s/%s matched all expected annotations %v", namespace, workloadName, expectedAnnotations)
	for i, ev := range events {
		t.Logf("  Event[%d]: reason=%s annotations=%v", i, ev.Reason, ev.Annotations)
	}
	t.FailNow()
}

// assertEventAnnotation asserts that a single event has the given annotation key and value.
func assertEventAnnotation(t *testing.T, event corev1.Event, key, expectedValue string) {
	t.Helper()
	require.NotNil(t, event.Annotations, "event %s has no annotations", event.Name)
	assert.Equal(t, expectedValue, event.Annotations[key],
		"event %s: annotation %s mismatch", event.Name, key)
}

// assertManagedByPotoo asserts that an event is managed by Potoo.
func assertManagedByPotoo(t *testing.T, event corev1.Event) {
	t.Helper()
	assertEventAnnotation(t, event, annotations.ManagedBy, annotations.ManagedByValue)
}

// applyUnstructured creates or updates an unstructured object in the cluster.
func applyUnstructured(t *testing.T, dynamicClient dynamic.Interface, obj *unstructured.Unstructured) {
	t.Helper()
	gvr := schema.GroupVersionResource{
		Group:    obj.GroupVersionKind().Group,
		Version:  obj.GroupVersionKind().Version,
		Resource: guessResource(obj.GetKind()),
	}

	ns := obj.GetNamespace()
	var err error
	if ns != "" {
		_, err = dynamicClient.Resource(gvr).Namespace(ns).Create(
			context.Background(), obj, metav1.CreateOptions{},
		)
	} else {
		_, err = dynamicClient.Resource(gvr).Create(
			context.Background(), obj, metav1.CreateOptions{},
		)
	}
	require.NoError(t, err, "failed to apply %s %s/%s", obj.GetKind(), ns, obj.GetName())
	t.Logf("Applied %s %s/%s", obj.GetKind(), ns, obj.GetName())
}

// deleteUnstructured deletes an unstructured object from the cluster.
func deleteUnstructured(t *testing.T, dynamicClient dynamic.Interface, gvr schema.GroupVersionResource, namespace, name string) {
	t.Helper()
	var err error
	if namespace != "" {
		err = dynamicClient.Resource(gvr).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	} else {
		err = dynamicClient.Resource(gvr).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
	if err != nil {
		t.Logf("Warning: failed to delete %s %s/%s: %v", gvr.Resource, namespace, name, err)
	}
}

// getControllerLogs retrieves the logs from the controller pod for debugging.
func getControllerLogs(t *testing.T, clientset kubernetes.Interface, tailLines int64) string {
	t.Helper()
	pods, err := clientset.CoreV1().Pods(controllerNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=controller",
	})
	if err != nil {
		t.Logf("Warning: failed to list controller pods: %v", err)
		return ""
	}
	if len(pods.Items) == 0 {
		t.Log("Warning: no controller pods found")
		return ""
	}

	pod := pods.Items[0]
	opts := &corev1.PodLogOptions{
		TailLines: &tailLines,
	}
	req := clientset.CoreV1().Pods(controllerNamespace).GetLogs(pod.Name, opts)
	stream, err := req.Stream(context.Background())
	if err != nil {
		t.Logf("Warning: failed to get logs for pod %s: %v", pod.Name, err)
		return ""
	}
	defer stream.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, stream); err != nil {
		t.Logf("Warning: failed to read logs for pod %s: %v", pod.Name, err)
		return ""
	}
	return buf.String()
}

// --- Correlation test helpers ---

// correlationEventTimeout is the time to wait for a Potoo ConstraintNotification event.
// Accounts for: informer sync + adapter parse + indexer upsert + event watch + correlation + dispatch.
// Use 180s: under full parallel load on single-node clusters (Docker Desktop), all 7
// test groups compete for controller cycles, making 120s marginal.
const correlationEventTimeout = 180 * time.Second

// workloadAnnotationTimeout is the time to wait for workload annotations to appear.
// Accounts for: indexer upsert + onChange callback + debounce (30s) + patch.
// Use 180s to accommodate parallel test contention on single-node clusters.
const workloadAnnotationTimeout = 180 * time.Second

// createTestDeployment creates a minimal Deployment using pause:3.9 in the given namespace.
// Returns a cleanup function that deletes the deployment.
func createTestDeployment(t *testing.T, dynamicClient dynamic.Interface, namespace, name string) func() {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					e2eLabel: "true",
				},
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": name,
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": name,
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "pause",
								"image": "registry.k8s.io/pause:3.9",
							},
						},
					},
				},
			},
		},
	}
	_, err := dynamicClient.Resource(depGVR).Namespace(namespace).Create(
		context.Background(), dep, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create test deployment %s/%s", namespace, name)
	t.Logf("Created test deployment: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(depGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// waitForPotooEvent polls for Kubernetes Events created by Potoo (Reason=ConstraintNotification,
// Source.Component=potoo-controller) that reference the given workload name.
func waitForPotooEvent(t *testing.T, clientset kubernetes.Interface, namespace, workloadName string, timeout time.Duration) []corev1.Event {
	t.Helper()
	var matched []corev1.Event

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		events, err := clientset.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("list events: %w", err)
		}
		matched = nil
		for _, ev := range events.Items {
			if ev.InvolvedObject.Name == workloadName &&
				ev.Reason == "ConstraintNotification" &&
				ev.Source.Component == "potoo-controller" {
				matched = append(matched, ev)
			}
		}
		return len(matched) > 0, nil
	})
	return matched
}

// getPotooEvents returns Potoo ConstraintNotification events for a workload
// without waiting. Use this for counting events after a known wait period.
func getPotooEvents(t *testing.T, clientset kubernetes.Interface, namespace, workloadName string) []corev1.Event {
	t.Helper()
	events, err := clientset.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err, "failed to list events in %s", namespace)

	var matched []corev1.Event
	for _, ev := range events.Items {
		if ev.InvolvedObject.Name == workloadName &&
			ev.Reason == "ConstraintNotification" &&
			ev.Source.Component == "potoo-controller" {
			matched = append(matched, ev)
		}
	}
	return matched
}

// waitForPotooEventByAnnotation polls for Potoo events that match a specific
// annotation key-value pair. Because the dispatcher rate-limits per namespace and
// drops excess notifications (non-blocking Allow()), a single warning event may not
// produce an event for every constraint. This function periodically re-sends warning
// events to give the rate limiter time to recover and process additional constraints.
func waitForPotooEventByAnnotation(t *testing.T, clientset kubernetes.Interface, namespace, workloadName, annotKey, annotValue string, timeout time.Duration) []corev1.Event {
	t.Helper()
	var matched []corev1.Event
	deadline := time.Now().Add(timeout)
	retryInterval := 3 * time.Second
	lastWarning := time.Time{}

	for time.Now().Before(deadline) {
		events, err := clientset.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Logf("waitForPotooEventByAnnotation: list events: %v", err)
			time.Sleep(defaultPollInterval)
			continue
		}
		matched = nil
		for _, ev := range events.Items {
			if ev.InvolvedObject.Name == workloadName &&
				ev.Reason == "ConstraintNotification" &&
				ev.Source.Component == "potoo-controller" &&
				ev.Annotations != nil &&
				ev.Annotations[annotKey] == annotValue {
				matched = append(matched, ev)
			}
		}
		if len(matched) > 0 {
			return matched
		}

		// Re-send a warning event to trigger another round of correlation.
		// Each new warning has a unique UID, so the correlator re-emits all
		// constraints, giving the rate limiter another chance to process the one we want.
		if time.Since(lastWarning) >= retryInterval {
			createWarningEvent(t, clientset, namespace, workloadName, "Deployment")
			lastWarning = time.Now()
		}

		time.Sleep(defaultPollInterval)
	}

	t.Fatalf("waitForPotooEventByAnnotation: timed out after %v waiting for %s=%s on workload %s", timeout, annotKey, annotValue, workloadName)
	return nil
}

// createWarningEvent creates a synthetic Warning event referencing the given involved object.
// This triggers the Correlator's event watch (FieldSelector: type=Warning).
func createWarningEvent(t *testing.T, clientset kubernetes.Interface, namespace, involvedName, involvedKind string) *corev1.Event {
	t.Helper()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-warning-",
			Namespace:    namespace,
			Labels: map[string]string{
				e2eLabel: "true",
			},
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      involvedKind,
			Namespace: namespace,
			Name:      involvedName,
		},
		Reason:         "E2ETestWarning",
		Message:        "Synthetic warning event for E2E correlation testing",
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: "e2e-test"},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}
	created, err := clientset.CoreV1().Events(namespace).Create(context.Background(), event, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create warning event for %s/%s", namespace, involvedName)
	t.Logf("Created warning event: %s", created.Name)
	return created
}

// waitForWorkloadAnnotation polls a deployment until the specified annotation key
// is present, then returns its value.
func waitForWorkloadAnnotation(t *testing.T, dynamicClient dynamic.Interface, namespace, deploymentName, annotationKey string, timeout time.Duration) string {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	var value string

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		dep, err := dynamicClient.Resource(depGVR).Namespace(namespace).Get(
			context.Background(), deploymentName, metav1.GetOptions{},
		)
		if err != nil {
			return false, fmt.Errorf("get deployment: %w", err)
		}
		annots := dep.GetAnnotations()
		if annots == nil {
			return false, nil
		}
		v, ok := annots[annotationKey]
		if !ok {
			return false, nil
		}
		value = v
		return true, nil
	})
	return value
}

// waitForStablePotooEventCount continuously sends warning events at 1s intervals
// to saturate the dispatcher dedup cache across all constraints. The dispatcher
// rate limiter (100/min, burst=10) allows ~1-2 events per warning after the initial
// burst. When all constraints are dedup'd, new warnings produce 0 new events.
//
// Returns the stable count when 15 consecutive seconds of warnings produce no growth.
func waitForStablePotooEventCount(t *testing.T, clientset kubernetes.Interface, namespace, workloadName string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	t.Log("Sending warnings to saturate dedup cache across all constraints")

	lastCount := 0
	lastGrowth := time.Now()

	for time.Now().Before(deadline) {
		// Send a warning — this triggers the correlator to emit notifications for
		// all constraints. The rate limiter allows ~1.67/sec through. If the
		// constraint is already dedup'd, no event is created.
		createWarningEvent(t, clientset, namespace, workloadName, "Deployment")
		time.Sleep(1 * time.Second)

		events := getPotooEvents(t, clientset, namespace, workloadName)
		currentCount := len(events)

		if currentCount > lastCount {
			t.Logf("Event count: %d (+%d)", currentCount, currentCount-lastCount)
			lastCount = currentCount
			lastGrowth = time.Now()
		}

		// If 30 seconds of continuous warnings produced no growth,
		// all constraints are in the dedup cache. Use 30s (not 15s) because
		// parallel tests create cluster-scoped constraints (Gatekeeper, Kyverno
		// ClusterPolicies) that can appear in this test's namespace mid-run.
		if time.Since(lastGrowth) >= 30*time.Second && lastCount > 0 {
			t.Logf("Event count stable at %d for 30s of continuous warnings", lastCount)
			return lastCount
		}
	}

	t.Fatalf("waitForStablePotooEventCount: timed out after %v; last count=%d", timeout, lastCount)
	return 0
}

// guessResource converts a Kind name to a plural resource name.
// Handles common Kubernetes kinds; extend as needed.
func guessResource(kind string) string {
	switch kind {
	case "NetworkPolicy":
		return "networkpolicies"
	case "ResourceQuota":
		return "resourcequotas"
	case "LimitRange":
		return "limitranges"
	case "Namespace":
		return "namespaces"
	case "Deployment":
		return "deployments"
	case "StatefulSet":
		return "statefulsets"
	case "DaemonSet":
		return "daemonsets"
	case "Service":
		return "services"
	case "ConfigMap":
		return "configmaps"
	case "Pod":
		return "pods"
	case "ValidatingWebhookConfiguration":
		return "validatingwebhookconfigurations"
	case "MutatingWebhookConfiguration":
		return "mutatingwebhookconfigurations"
	case "CustomResourceDefinition":
		return "customresourcedefinitions"
	case "AuthorizationPolicy":
		return "authorizationpolicies"
	case "PeerAuthentication":
		return "peerauthentications"
	case "Sidecar":
		return "sidecars"
	default:
		// Best-effort: lowercase + "s"
		return strings.ToLower(kind) + "s"
	}
}

// constraintSummary is a compact representation of a constraint for JSON deserialization.
// Mirrors notifier.ConstraintSummary.
type constraintSummary struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Name     string `json:"name"`
	Source   string `json:"source"`
}

// createSentinelDeployment creates a minimal Deployment in the given namespace
// that the workload annotator can target. Returns a cleanup function.
func createSentinelDeployment(t *testing.T, clientset kubernetes.Interface, namespace, name string) func() {
	t.Helper()
	replicas := int32(1)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "pause",
							Image:   "registry.k8s.io/pause:3.9",
							Command: []string{"/pause"},
						},
					},
				},
			},
		},
	}
	_, err := clientset.AppsV1().Deployments(namespace).Create(
		context.Background(), deploy, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create sentinel deployment %s/%s", namespace, name)
	t.Logf("Created sentinel deployment: %s/%s", namespace, name)

	return func() {
		err := clientset.AppsV1().Deployments(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
		if err != nil {
			t.Logf("Warning: failed to delete sentinel deployment %s/%s: %v", namespace, name, err)
		}
	}
}

// --- Webhook test helpers ---

const (
	// webhookDeploymentName is the name of the webhook Deployment in the E2E cluster.
	webhookDeploymentName = "potoo-webhook"

	// webhookServiceName is the name of the webhook Service.
	webhookServiceName = "potoo-webhook"

	// webhookConfigName is the name of the ValidatingWebhookConfiguration.
	webhookConfigName = "potoo-webhook"

	// webhookSecretName is the name of the TLS Secret for self-signed certs.
	webhookSecretName = "potoo-webhook-tls"

	// webhookReadyTimeout is time to wait for the webhook to become fully ready
	// (deployment + VWC caBundle injected).
	webhookReadyTimeout = 120 * time.Second
)

// waitForWebhookReady waits for the webhook Deployment to have ready replicas
// AND the ValidatingWebhookConfiguration to have a non-empty caBundle.
func waitForWebhookReady(t *testing.T, clientset kubernetes.Interface, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for webhook deployment %s/%s to become ready...", controllerNamespace, webhookDeploymentName)

	// First wait for Deployment readiness.
	waitForDeploymentReady(t, clientset, controllerNamespace, webhookDeploymentName, timeout)

	// Then wait for VWC caBundle to be populated (self-signed cert injection).
	t.Log("Waiting for ValidatingWebhookConfiguration caBundle to be populated...")
	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		vwc, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(
			context.Background(), webhookConfigName, metav1.GetOptions{},
		)
		if err != nil {
			return false, fmt.Errorf("get VWC: %w", err)
		}
		if len(vwc.Webhooks) == 0 {
			return false, nil
		}
		caBundle := vwc.Webhooks[0].ClientConfig.CABundle
		if len(caBundle) == 0 {
			return false, nil
		}
		t.Logf("VWC caBundle populated (%d bytes)", len(caBundle))
		return true, nil
	})
}

// getValidatingWebhookConfig returns the ValidatingWebhookConfiguration for
// the potoo webhook.
func getValidatingWebhookConfig(t *testing.T, clientset kubernetes.Interface) *admissionregistrationv1.ValidatingWebhookConfiguration {
	t.Helper()
	vwc, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(
		context.Background(), webhookConfigName, metav1.GetOptions{},
	)
	require.NoError(t, err, "failed to get ValidatingWebhookConfiguration %s", webhookConfigName)
	return vwc
}

// getTLSSecret returns the webhook TLS Secret.
func getTLSSecret(t *testing.T, clientset kubernetes.Interface) *corev1.Secret {
	t.Helper()
	secret, err := clientset.CoreV1().Secrets(controllerNamespace).Get(
		context.Background(), webhookSecretName, metav1.GetOptions{},
	)
	require.NoError(t, err, "failed to get TLS secret %s/%s", controllerNamespace, webhookSecretName)
	return secret
}

// getWebhookLogs retrieves logs from the webhook pods for debugging.
func getWebhookLogs(t *testing.T, clientset kubernetes.Interface, tailLines int64) string {
	t.Helper()
	pods, err := clientset.CoreV1().Pods(controllerNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=webhook",
	})
	if err != nil {
		t.Logf("Warning: failed to list webhook pods: %v", err)
		return ""
	}
	if len(pods.Items) == 0 {
		t.Log("Warning: no webhook pods found")
		return ""
	}

	var allLogs strings.Builder
	for _, pod := range pods.Items {
		opts := &corev1.PodLogOptions{TailLines: &tailLines}
		stream, err := clientset.CoreV1().Pods(controllerNamespace).GetLogs(pod.Name, opts).Stream(context.Background())
		if err != nil {
			t.Logf("Warning: failed to get logs for webhook pod %s: %v", pod.Name, err)
			continue
		}
		var buf bytes.Buffer
		io.Copy(&buf, stream)
		stream.Close()
		allLogs.WriteString(fmt.Sprintf("=== %s ===\n%s\n", pod.Name, buf.String()))
	}
	return allLogs.String()
}

// getWebhookPDB returns the PodDisruptionBudget for the webhook, or nil if not found.
func getWebhookPDB(t *testing.T, clientset kubernetes.Interface) *policyv1.PodDisruptionBudget {
	t.Helper()
	pdb, err := clientset.PolicyV1().PodDisruptionBudgets(controllerNamespace).Get(
		context.Background(), webhookDeploymentName, metav1.GetOptions{},
	)
	if err != nil {
		return nil
	}
	return pdb
}

// scaleDeployment scales a deployment to the given replicas and waits for it to settle.
func scaleDeployment(t *testing.T, clientset kubernetes.Interface, namespace, name string, replicas int32) {
	t.Helper()
	deploy, err := clientset.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
	require.NoError(t, err, "get deployment %s/%s", namespace, name)

	deploy.Spec.Replicas = &replicas
	_, err = clientset.AppsV1().Deployments(namespace).Update(context.Background(), deploy, metav1.UpdateOptions{})
	require.NoError(t, err, "scale deployment %s/%s to %d", namespace, name, replicas)
	t.Logf("Scaled %s/%s to %d replicas", namespace, name, replicas)
}

// getWorkloadConstraints parses the potoo.io/constraints JSON annotation
// from a Deployment and returns the decoded constraint summaries.
func getWorkloadConstraints(t *testing.T, dynamicClient dynamic.Interface, namespace, deploymentName string, timeout time.Duration) []constraintSummary {
	t.Helper()
	raw := waitForWorkloadAnnotation(t, dynamicClient, namespace, deploymentName,
		annotations.WorkloadConstraints, timeout)

	var summaries []constraintSummary
	require.NoError(t, json.Unmarshal([]byte(raw), &summaries),
		"failed to parse constraints JSON: %s", raw)
	return summaries
}

// waitForConstraintMatch polls the workload annotations until a constraint matching
// the predicate appears. Unlike getWorkloadConstraints (which returns as soon as ANY
// annotation exists), this helper ensures the specific constraint is present — critical
// for tests where the discovery engine needs a CRD rescan cycle before the constraint
// appears.
func waitForConstraintMatch(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, deploymentName string,
	timeout time.Duration,
	matchFn func(constraintSummary) bool,
) []constraintSummary {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	var summaries []constraintSummary

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		dep, err := dynamicClient.Resource(depGVR).Namespace(namespace).Get(
			context.Background(), deploymentName, metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		annots := dep.GetAnnotations()
		if annots == nil {
			return false, nil
		}
		raw, ok := annots[annotations.WorkloadConstraints]
		if !ok {
			return false, nil
		}
		var current []constraintSummary
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return false, fmt.Errorf("unmarshal constraints annotation: %w", err)
		}
		for _, c := range current {
			if matchFn(c) {
				summaries = current
				return true, nil
			}
		}
		return false, nil
	})
	return summaries
}

// createAnnotatorTrigger creates a namespace-scoped NetworkPolicy to force the
// workload annotator to process the given namespace. Cluster-scoped constraints
// (like Gatekeeper constraints, webhooks) need this trigger because OnIndexChange
// doesn't queue a namespace update for them.
func createAnnotatorTrigger(t *testing.T, dynamicClient dynamic.Interface, namespace, name string) func() {
	t.Helper()
	np := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"policyTypes": []interface{}{"Ingress"},
			},
		},
	}
	applyUnstructured(t, dynamicClient, np)
	return func() {
		deleteUnstructured(t, dynamicClient, schema.GroupVersionResource{
			Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies",
		}, namespace, name)
	}
}

// --- ConstraintProfile / generic adapter E2E helpers ---

// constraintProfileGVR is the GVR for the ConstraintProfile CRD.
var constraintProfileGVR = schema.GroupVersionResource{
	Group:    "potoo.io",
	Version:  "v1alpha1",
	Resource: "constraintprofiles",
}

// crdEstablishTimeout is the default timeout for waiting for a CRD to become established.
const crdEstablishTimeout = 60 * time.Second

// waitForCRDReady polls a CRD by name until its status conditions include Established=True.
func waitForCRDReady(t *testing.T, dynamicClient dynamic.Interface, crdName string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for CRD %s to become established...", crdName)

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		obj, err := dynamicClient.Resource(crdGVR).Get(
			context.Background(), crdName, metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		conditions, ok, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
		if !ok || conditions == nil {
			return false, nil
		}
		for _, condRaw := range conditions {
			cond, ok := condRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if cond["type"] == "Established" && cond["status"] == "True" {
				t.Logf("CRD %s is established", crdName)
				return true, nil
			}
		}
		return false, nil
	})
}

// createCustomCRD creates a namespaced CRD with x-kubernetes-preserve-unknown-fields for testing.
// Returns the full CRD name (<resource>.<group>) and a cleanup function.
// The CRD uses a permissive schema so arbitrary spec fields can be used in tests.
func createCustomCRD(
	t *testing.T,
	dynamicClient dynamic.Interface,
	group, version, kind, resource string,
	crdAnnotations map[string]interface{},
) (string, func()) {
	t.Helper()
	crdName := resource + "." + group

	// Delete any leftover CRD from a previous run.
	_ = dynamicClient.Resource(crdGVR).Delete(context.Background(), crdName, metav1.DeleteOptions{})
	waitForCondition(t, 30*time.Second, defaultPollInterval, func() (bool, error) {
		_, err := dynamicClient.Resource(crdGVR).Get(context.Background(), crdName, metav1.GetOptions{})
		if err != nil {
			return true, nil // CRD is gone
		}
		return false, nil
	})

	meta := map[string]interface{}{
		"name": crdName,
	}
	if len(crdAnnotations) > 0 {
		meta["annotations"] = crdAnnotations
	}

	crd := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata":   meta,
			"spec": map[string]interface{}{
				"group": group,
				"names": map[string]interface{}{
					"plural":   resource,
					"singular": strings.ToLower(kind),
					"kind":     kind,
				},
				"scope": "Namespaced",
				"versions": []interface{}{
					map[string]interface{}{
						"name":    version,
						"served":  true,
						"storage": true,
						"schema": map[string]interface{}{
							"openAPIV3Schema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"spec": map[string]interface{}{
										"type":                                 "object",
										"x-kubernetes-preserve-unknown-fields": true,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := dynamicClient.Resource(crdGVR).Create(
		context.Background(), crd, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create CRD %s", crdName)
	t.Logf("Created CRD: %s", crdName)

	// Wait for establishment.
	waitForCRDReady(t, dynamicClient, crdName, crdEstablishTimeout)

	cleanup := func() {
		_ = dynamicClient.Resource(crdGVR).Delete(
			context.Background(), crdName, metav1.DeleteOptions{},
		)
		t.Logf("Deleted CRD: %s", crdName)
	}
	return crdName, cleanup
}

// createCRInstance creates a namespaced instance of a custom CRD. Returns a cleanup function.
// Uses explicit GVR to avoid guessResource pluralization issues.
func createCRInstance(
	t *testing.T,
	dynamicClient dynamic.Interface,
	gvr schema.GroupVersionResource,
	apiVersion, kind, namespace, name string,
	spec map[string]interface{},
	crAnnotations map[string]interface{},
) func() {
	t.Helper()

	meta := map[string]interface{}{
		"name":      name,
		"namespace": namespace,
	}
	if len(crAnnotations) > 0 {
		meta["annotations"] = crAnnotations
	}

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata":   meta,
			"spec":       spec,
		},
	}

	// Retry briefly — CRD may still be registering with the API server.
	var createErr error
	waitForCondition(t, 15*time.Second, defaultPollInterval, func() (bool, error) {
		_, createErr = dynamicClient.Resource(gvr).Namespace(namespace).Create(
			context.Background(), cr, metav1.CreateOptions{},
		)
		return createErr == nil, nil
	})
	require.NoError(t, createErr, "failed to create %s %s/%s", kind, namespace, name)
	t.Logf("Created %s: %s/%s", kind, namespace, name)

	return func() {
		_ = dynamicClient.Resource(gvr).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createConstraintProfile creates a cluster-scoped ConstraintProfile. Returns a cleanup function.
func createConstraintProfile(
	t *testing.T,
	dynamicClient dynamic.Interface,
	name string,
	spec map[string]interface{},
) func() {
	t.Helper()

	profile := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "potoo.io/v1alpha1",
			"kind":       "ConstraintProfile",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": spec,
		},
	}

	_, err := dynamicClient.Resource(constraintProfileGVR).Create(
		context.Background(), profile, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create ConstraintProfile %s", name)
	t.Logf("Created ConstraintProfile: %s", name)

	return func() {
		_ = dynamicClient.Resource(constraintProfileGVR).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
		t.Logf("Deleted ConstraintProfile: %s", name)
	}
}

// updateConstraintProfile gets a ConstraintProfile by name, applies a mutation function,
// and updates it. The mutationFn receives the current object and should modify it in place.
func updateConstraintProfile(
	t *testing.T,
	dynamicClient dynamic.Interface,
	name string,
	mutationFn func(obj *unstructured.Unstructured),
) {
	t.Helper()

	obj, err := dynamicClient.Resource(constraintProfileGVR).Get(
		context.Background(), name, metav1.GetOptions{},
	)
	require.NoError(t, err, "failed to get ConstraintProfile %s for update", name)

	mutationFn(obj)

	_, err = dynamicClient.Resource(constraintProfileGVR).Update(
		context.Background(), obj, metav1.UpdateOptions{},
	)
	require.NoError(t, err, "failed to update ConstraintProfile %s", name)
	t.Logf("Updated ConstraintProfile: %s", name)
}

// waitForNoConstraintMatch polls the workload annotations until NO constraint matching
// the predicate is found. This accounts for propagation delay after profile/constraint
// deletion — the annotator needs time to reconcile before the constraint disappears.
func waitForNoConstraintMatch(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, deploymentName string,
	timeout time.Duration,
	matchFn func(constraintSummary) bool,
) {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		dep, err := dynamicClient.Resource(depGVR).Namespace(namespace).Get(
			context.Background(), deploymentName, metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		annots := dep.GetAnnotations()
		if annots == nil {
			return true, nil // No annotations at all — constraint is gone
		}
		raw, ok := annots[annotations.WorkloadConstraints]
		if !ok {
			return true, nil // No constraints annotation — constraint is gone
		}
		var current []constraintSummary
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return false, nil
		}
		for _, c := range current {
			if matchFn(c) {
				return false, nil // Still found — keep polling
			}
		}
		return true, nil // Not found anymore — success
	})
}

// --- Missing resource detection helpers ---

// requirementDetectionTimeout is the time to wait for a missing-resource constraint
// to appear in the ConstraintReport. Accounts for: requirement debounce (10s in E2E) +
// report reconcile cycle (3s debounce + tick) + CI contention.
const requirementDetectionTimeout = 180 * time.Second

// createDeploymentWithMetricsPort creates a minimal Deployment with a container port
// named "metrics" to trigger the prometheus-monitor requirement rule.
func createDeploymentWithMetricsPort(t *testing.T, dynamicClient dynamic.Interface, namespace, name string) func() {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					e2eLabel: "true",
				},
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": name,
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": name,
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "registry.k8s.io/pause:3.9",
								"ports": []interface{}{
									map[string]interface{}{
										"name":          "metrics",
										"containerPort": int64(9090),
										"protocol":      "TCP",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	_, err := dynamicClient.Resource(depGVR).Namespace(namespace).Create(
		context.Background(), dep, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create deployment with metrics port %s/%s", namespace, name)
	t.Logf("Created deployment with metrics port: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(depGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createDeploymentWithAnnotations creates a minimal Deployment with the given annotations
// on the pod template.
func createDeploymentWithAnnotations(t *testing.T, dynamicClient dynamic.Interface, namespace, name string, annotations map[string]interface{}) func() {
	t.Helper()
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	// Build pod template annotations.
	podMeta := map[string]interface{}{
		"labels": map[string]interface{}{
			"app": name,
		},
	}
	if len(annotations) > 0 {
		podMeta["annotations"] = annotations
	}

	dep := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					e2eLabel: "true",
				},
				"annotations": annotations,
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": name,
					},
				},
				"template": map[string]interface{}{
					"metadata": podMeta,
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "pause",
								"image": "registry.k8s.io/pause:3.9",
							},
						},
					},
				},
			},
		},
	}
	_, err := dynamicClient.Resource(depGVR).Namespace(namespace).Create(
		context.Background(), dep, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create deployment with annotations %s/%s", namespace, name)
	t.Logf("Created deployment with annotations: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(depGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// requireCRDInstalled skips the test if the given CRD is not installed in the cluster.
// crdFullName should be e.g. "servicemonitors.monitoring.coreos.com".
func requireCRDInstalled(t *testing.T, dynamicClient dynamic.Interface, crdFullName string) {
	t.Helper()
	_, err := dynamicClient.Resource(crdGVR).Get(
		context.Background(), crdFullName, metav1.GetOptions{},
	)
	if err != nil {
		t.Skipf("Skipping: CRD %s not installed", crdFullName)
	}
}

// missingResourceEntry mirrors v1alpha1.MissingResourceEntry for JSON deserialization.
type missingResourceEntry struct {
	ExpectedKind       string `json:"expectedKind"`
	ExpectedAPIVersion string `json:"expectedAPIVersion"`
	Reason             string `json:"reason"`
	Severity           string `json:"severity"`
	ForWorkload        struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"forWorkload"`
}

// waitForMissingResource polls the ConstraintReport's machineReadable.missingResources
// section until an entry matching the predicate appears.
func waitForMissingResource(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace string,
	timeout time.Duration,
	matchFn func(entry map[string]interface{}) bool,
) map[string]interface{} {
	t.Helper()
	var matched map[string]interface{}

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		obj, err := dynamicClient.Resource(constraintReportGVR).Namespace(namespace).Get(
			context.Background(), "constraints", metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		mr, ok, _ := unstructured.NestedMap(obj.Object, "status", "machineReadable")
		if !ok || mr == nil {
			return false, nil
		}
		entries, ok, _ := unstructured.NestedSlice(mr, "missingResources")
		if !ok {
			return false, nil
		}
		for _, raw := range entries {
			entry, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if matchFn(entry) {
				matched = entry
				return true, nil
			}
		}
		return false, nil
	})
	return matched
}

// waitForNoMissingResource verifies that no missingResources entry matching the
// predicate appears in the ConstraintReport within the given timeout. The caller
// should first establish that the report exists (e.g., via another constraint).
func waitForNoMissingResource(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace string,
	stableWindow time.Duration,
	matchFn func(entry map[string]interface{}) bool,
) {
	t.Helper()
	deadline := time.Now().Add(stableWindow)
	for time.Now().Before(deadline) {
		obj, err := dynamicClient.Resource(constraintReportGVR).Namespace(namespace).Get(
			context.Background(), "constraints", metav1.GetOptions{},
		)
		if err != nil {
			time.Sleep(defaultPollInterval)
			continue
		}
		mr, ok, _ := unstructured.NestedMap(obj.Object, "status", "machineReadable")
		if !ok || mr == nil {
			time.Sleep(defaultPollInterval)
			continue
		}
		entries, ok, _ := unstructured.NestedSlice(mr, "missingResources")
		if ok {
			for _, raw := range entries {
				entry, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				if matchFn(entry) {
					t.Fatalf("unexpected missingResources entry found: %v", entry)
				}
			}
		}
		time.Sleep(defaultPollInterval)
	}
}

// patchNamespaceLabel patches a namespace to add or update a label.
func patchNamespaceLabel(t *testing.T, clientset kubernetes.Interface, namespace, key, value string) {
	t.Helper()
	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	require.NoError(t, err, "failed to get namespace %s", namespace)

	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	ns.Labels[key] = value

	_, err = clientset.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	require.NoError(t, err, "failed to patch namespace label %s=%s on %s", key, value, namespace)
	t.Logf("Patched namespace %s: %s=%s", namespace, key, value)
}

// --- MCP server E2E helpers ---

// mcpServiceName is the K8s service name for the controller (must match Helm fullname).
const mcpServiceName = "potoo"

// mcpPortForwardTimeout is the max time to wait for the port-forward to become ready.
const mcpPortForwardTimeout = 30 * time.Second

// mcpQueryTimeout is the max time to wait for constraints to appear via MCP query.
const mcpQueryTimeout = 180 * time.Second

// mcpHTTPRetries is the number of retries for transient HTTP errors (connection refused).
const mcpHTTPRetries = 5

// mcpHTTPRetryDelay is the delay between HTTP retries after a reconnect.
const mcpHTTPRetryDelay = 3 * time.Second

// syncBuffer is a goroutine-safe bytes.Buffer for capturing command output
// without data races between the exec goroutine and the polling loop.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

// mcpPortForward manages a kubectl port-forward process with auto-reconnect.
// Under heavy parallel test load, the port-forward subprocess can die when the
// API server connection is disrupted. This wrapper detects process death and
// automatically restarts it, updating the URL atomically.
type mcpPortForward struct {
	t      *testing.T
	mu     sync.RWMutex
	url    string
	cancel context.CancelFunc
	done   chan struct{} // closed when the manager is stopped
}

// URL returns the current base URL for the MCP server port-forward.
func (pf *mcpPortForward) URL() string {
	pf.mu.RLock()
	defer pf.mu.RUnlock()
	return pf.url
}

func (pf *mcpPortForward) setURL(url string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.url = url
}

// startMCPPortForward starts a kubectl port-forward to the controller Service's MCP
// port (8090) with automatic reconnection on process death. Returns an
// *mcpPortForward whose URL() method always reflects the current forwarded port.
// Registers cleanup via t.Cleanup.
func startMCPPortForward(t *testing.T) *mcpPortForward {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	pf := &mcpPortForward{
		t:      t,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	// Start the initial port-forward.
	url := launchPortForward(t, ctx)
	pf.setURL(url)

	// Watchdog: monitor the port-forward and restart on death.
	go pf.watchdog(ctx)

	t.Cleanup(func() {
		cancel()
		<-pf.done
		t.Logf("Stopped kubectl port-forward")
	})

	return pf
}

// watchdog monitors the port-forward health and restarts it on failure.
func (pf *mcpPortForward) watchdog(ctx context.Context) {
	defer close(pf.done)
	client := &http.Client{Timeout: 2 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		url := pf.URL()
		if url == "" {
			continue
		}

		resp, err := client.Get(url + "/resources/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				continue // healthy
			}
		}

		// Port-forward appears dead — restart it.
		pf.t.Logf("MCP port-forward health check failed, reconnecting...")
		newURL := launchPortForward(pf.t, ctx)
		if newURL != "" {
			pf.setURL(newURL)
			pf.t.Logf("MCP port-forward reconnected: %s", newURL)
		}
	}
}

// launchPortForward starts a single kubectl port-forward process and waits for
// it to become ready. Returns the base URL or empty string on failure.
func launchPortForward(t *testing.T, ctx context.Context) string {
	t.Helper()

	cmd := exec.CommandContext(ctx,
		"kubectl", "port-forward",
		fmt.Sprintf("svc/%s", mcpServiceName),
		"0:8090",
		"-n", controllerNamespace,
	)

	stderr := &syncBuffer{}
	stdout := &syncBuffer{}
	cmd.Stderr = stderr
	cmd.Stdout = stdout

	if err := cmd.Start(); err != nil {
		t.Logf("failed to start kubectl port-forward: %v", err)
		return ""
	}
	t.Logf("Started kubectl port-forward (pid=%d)", cmd.Process.Pid)

	// Ensure process cleanup on context cancellation.
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	// Poll for the "Forwarding from" line.
	var localPort string
	deadline := time.Now().Add(mcpPortForwardTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ""
		}
		output := stderr.String() + stdout.String()
		if port := parseForwardedPort(output); port != "" {
			localPort = port
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if localPort == "" {
		t.Logf("kubectl port-forward did not report a local port within %v\nstderr: %s\nstdout: %s",
			mcpPortForwardTimeout, stderr.String(), stdout.String())
		return ""
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%s", localPort)
	t.Logf("MCP port-forward ready: %s -> svc/%s:8090", baseURL, mcpServiceName)

	// Wait for the MCP server to respond.
	client := &http.Client{Timeout: 2 * time.Second}
	readyDeadline := time.Now().Add(mcpPortForwardTimeout)
	for time.Now().Before(readyDeadline) {
		if ctx.Err() != nil {
			return ""
		}
		resp, err := client.Get(baseURL + "/resources/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Log("MCP health endpoint is ready")
				return baseURL
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("MCP health endpoint not ready after %v", mcpPortForwardTimeout)
	return ""
}

// parseForwardedPort extracts the local port from kubectl port-forward output.
// Handles both IPv4 ("Forwarding from 127.0.0.1:<port>") and IPv6 ("Forwarding from [::1]:<port>").
func parseForwardedPort(output string) string {
	for _, prefix := range []string{"Forwarding from 127.0.0.1:", "Forwarding from [::1]:"} {
		if idx := strings.Index(output, prefix); idx >= 0 {
			rest := output[idx+len(prefix):]
			if end := strings.Index(rest, " "); end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

// mcpDoGet performs an HTTP GET with retry on transient connection errors.
func mcpDoGet(pf *mcpPortForward, path string) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	for attempt := range mcpHTTPRetries {
		url := pf.URL()
		resp, err := client.Get(url + path)
		if err == nil {
			return resp, nil
		}
		if !isTransientConnError(err) || attempt == mcpHTTPRetries-1 {
			return nil, err
		}
		time.Sleep(mcpHTTPRetryDelay)
	}
	return nil, fmt.Errorf("mcpDoGet %s: all retries exhausted", path)
}

// mcpDoPost performs an HTTP POST with retry on transient connection errors.
func mcpDoPost(pf *mcpPortForward, path string, payload []byte) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	for attempt := range mcpHTTPRetries {
		url := pf.URL()
		resp, err := client.Post(url+path, "application/json", bytes.NewReader(payload))
		if err == nil {
			return resp, nil
		}
		if !isTransientConnError(err) || attempt == mcpHTTPRetries-1 {
			return nil, err
		}
		time.Sleep(mcpHTTPRetryDelay)
	}
	return nil, fmt.Errorf("mcpDoPost %s: all retries exhausted", path)
}

// isTransientConnError returns true for connection refused / reset errors that
// indicate the port-forward died and may be reconnecting.
func isTransientConnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") || strings.Contains(s, "connection reset")
}

// mcpGet performs an HTTP GET to the MCP server and returns the parsed JSON body.
func mcpGet(t *testing.T, pf *mcpPortForward, path string) map[string]interface{} {
	t.Helper()
	resp, err := mcpDoGet(pf, path)
	require.NoError(t, err, "MCP GET %s failed", path)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "MCP GET %s returned %d", path, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result), "MCP GET %s: invalid JSON", path)
	return result
}

// mcpPost performs an HTTP POST to the MCP server with a JSON body and returns
// the parsed JSON response.
func mcpPost(t *testing.T, pf *mcpPortForward, path string, body interface{}) map[string]interface{} {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err, "failed to marshal MCP POST body")

	resp, err := mcpDoPost(pf, path, payload)
	require.NoError(t, err, "MCP POST %s failed", path)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "MCP POST %s returned %d", path, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result), "MCP POST %s: invalid JSON", path)
	return result
}

// mcpPostArray performs an HTTP POST to the MCP server and returns a JSON array response.
func mcpPostArray(t *testing.T, pf *mcpPortForward, path string, body interface{}) []interface{} {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err, "failed to marshal MCP POST body")

	resp, err := mcpDoPost(pf, path, payload)
	require.NoError(t, err, "MCP POST %s failed", path)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "MCP POST %s returned %d", path, resp.StatusCode)

	var result []interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result), "MCP POST %s: invalid JSON array", path)
	return result
}

// waitForMCPConstraint polls the MCP query endpoint until at least one constraint
// matching matchFn appears in the response for the given namespace.
func waitForMCPConstraint(
	t *testing.T,
	pf *mcpPortForward, namespace string,
	timeout time.Duration,
	matchFn func(constraint map[string]interface{}) bool,
) map[string]interface{} {
	t.Helper()
	var matched map[string]interface{}

	waitForCondition(t, timeout, 2*time.Second, func() (bool, error) {
		payload, err := json.Marshal(map[string]string{"namespace": namespace})
		if err != nil {
			return false, err
		}
		resp, err := mcpDoPost(pf, "/tools/potoo_query", payload)
		if err != nil {
			// Transient errors during reconnect — keep polling.
			return false, nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("MCP query returned %d", resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, err
		}

		constraints, ok := result["constraints"].([]interface{})
		if !ok {
			return false, nil
		}
		for _, raw := range constraints {
			c, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if matchFn(c) {
				matched = c
				return true, nil
			}
		}
		return false, nil
	})
	return matched
}
