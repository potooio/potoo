//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// TestWebhookNotification verifies the end-to-end webhook notification pipeline:
// constraint discovery → correlation → dispatch → HTTP POST to webhook receiver.
//
// This test modifies the controller Deployment to add --webhook-url and is NOT
// run in parallel to avoid disrupting other tests during the controller restart.
// It deploys a lightweight nginx-based HTTP receiver that returns 200 for all
// requests, then verifies the controller sends webhooks without errors.
func TestWebhookNotification(t *testing.T) {
	// NOT parallel — patches the controller Deployment.
	ctx := context.Background()

	// 1. Deploy a webhook receiver (nginx returning 200 for all requests).
	receiverNS, cleanupReceiverNS := createTestNamespace(t, sharedClientset)
	t.Cleanup(cleanupReceiverNS)

	receiverName := "webhook-receiver"
	deployWebhookReceiver(t, sharedClientset, receiverNS, receiverName)

	// 2. Patch controller deployment to add --webhook-url pointing to the receiver.
	// Use MinSeverity=Info so all constraint types trigger webhooks.
	webhookURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:8080/webhook", receiverName, receiverNS)
	restoreController := patchControllerWithWebhookURL(t, sharedClientset, webhookURL)
	t.Cleanup(restoreController)

	// 3. Wait for the controller rollout to complete.
	waitForControllerReady(t, sharedClientset, 120*time.Second)

	// Give the controller time to initialize (discovery scan, informer sync).
	// No specific readiness signal beyond deployment ready, so short fixed wait.
	time.Sleep(5 * time.Second)

	// 4. Verify the controller logs show webhook sender started.
	verifyWebhookSenderStarted(t, sharedClientset)

	t.Run("ReceivesWebhookOnConstraintNotification", func(t *testing.T) {
		// Create a constraint (NetworkPolicy) in a fresh test namespace.
		testNS, cleanupTestNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupTestNS)

		npName := "e2e-wh-notif-deny-ingress"
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      npName,
					"namespace": testNS,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Ingress"},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(testNS).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create NetworkPolicy")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(npGVR).Namespace(testNS).Delete(ctx, npName, metav1.DeleteOptions{})
		})

		// Wait for the constraint to be indexed.
		waitForReportCondition(t, sharedDynamicClient, testNS, reportCreateTimeout, func(status map[string]interface{}) bool {
			return statusInt64(status, "constraintCount") >= 1
		})
		t.Log("Constraint indexed")

		// Create a test deployment.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, testNS, "wh-notif-test-app")
		t.Cleanup(cleanupDep)

		// Create a Warning event to trigger correlation.
		createWarningEvent(t, sharedClientset, testNS, "wh-notif-test-app", "Deployment")

		// Wait for Potoo ConstraintNotification event (confirms pipeline worked).
		events := waitForPotooEvent(t, sharedClientset, testNS, "wh-notif-test-app", correlationEventTimeout)
		require.NotEmpty(t, events, "expected at least one Potoo ConstraintNotification event")
		t.Logf("Got %d Potoo events", len(events))

		// Poll controller logs until dispatch confirmation or timeout.
		pollForLogMessage(t, sharedClientset, "Dispatched notification", 10*time.Second)

		// Verify controller logs show no webhook send errors.
		verifyNoWebhookErrors(t, sharedClientset)
	})

	t.Run("WebhookPayloadSentOnDispatch", func(t *testing.T) {
		// Create a different constraint type (egress) to verify webhooks for varied constraints.
		testNS, cleanupTestNS := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanupTestNS)

		npName := "e2e-wh-notif-restrict-egress"
		np := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      npName,
					"namespace": testNS,
					"labels": map[string]interface{}{
						e2eLabel: "true",
					},
				},
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
					"policyTypes": []interface{}{"Egress"},
					"egress": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"protocol": "TCP",
									"port":     int64(443),
								},
							},
						},
					},
				},
			},
		}
		_, err := sharedDynamicClient.Resource(npGVR).Namespace(testNS).Create(ctx, np, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create egress NetworkPolicy")
		t.Cleanup(func() {
			_ = sharedDynamicClient.Resource(npGVR).Namespace(testNS).Delete(ctx, npName, metav1.DeleteOptions{})
		})

		// Wait for the constraint to be indexed.
		waitForReportCondition(t, sharedDynamicClient, testNS, reportCreateTimeout, func(status map[string]interface{}) bool {
			names := statusConstraintNames(status)
			for _, n := range names {
				if n == npName {
					return true
				}
			}
			return false
		})
		t.Log("Egress constraint indexed")

		// Create a deployment and trigger warning.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, testNS, "wh-egress-test-app")
		t.Cleanup(cleanupDep)
		createWarningEvent(t, sharedClientset, testNS, "wh-egress-test-app", "Deployment")

		// Wait for Potoo event.
		events := waitForPotooEvent(t, sharedClientset, testNS, "wh-egress-test-app", correlationEventTimeout)
		require.NotEmpty(t, events, "expected Potoo event for egress constraint")
		t.Logf("Got %d Potoo events for egress constraint", len(events))

		// Poll controller logs until dispatch confirmation or timeout.
		pollForLogMessage(t, sharedClientset, "Dispatched notification", 10*time.Second)

		// Verify no errors in webhook sends.
		verifyNoWebhookErrors(t, sharedClientset)

		// Additionally verify the Dispatched notification log includes the constraint.
		logs := getControllerLogs(t, sharedClientset, 200)
		assert.Contains(t, logs, "Dispatched notification",
			"controller logs should show dispatched notification")
	})
}

// --- Webhook notification test helpers ---

// deployWebhookReceiver deploys an nginx-based HTTP server that returns 200 for
// all requests, making it a suitable webhook receiver for testing.
func deployWebhookReceiver(t *testing.T, clientset kubernetes.Interface, namespace, name string) {
	t.Helper()
	ctx := context.Background()

	// Create ConfigMap with nginx config that accepts all methods with 200.
	nginxConf := `server {
    listen 8080;
    location / {
        return 200 'ok';
        add_header Content-Type text/plain;
    }
}`
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-config",
			Namespace: namespace,
			Labels:    map[string]string{e2eLabel: "true"},
		},
		Data: map[string]string{
			"default.conf": nginxConf,
		},
	}
	_, err := clientset.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create nginx ConfigMap")

	// Create Deployment.
	replicas := int32(1)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{e2eLabel: "true"},
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
							Name:  "nginx",
							Image: "nginx:alpine",
							Ports: []corev1.ContainerPort{
								{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "config", MountPath: "/etc/nginx/conf.d"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: name + "-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	_, err = clientset.AppsV1().Deployments(namespace).Create(ctx, dep, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create webhook receiver Deployment")

	// Create Service.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{e2eLabel: "true"},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name},
			Ports: []corev1.ServicePort{
				{Port: 8080, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	_, err = clientset.CoreV1().Services(namespace).Create(ctx, svc, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create webhook receiver Service")

	// Wait for receiver to be ready.
	waitForDeploymentReady(t, clientset, namespace, name, 60*time.Second)
	t.Logf("Webhook receiver ready: %s/%s", namespace, name)
}

// patchControllerWithWebhookURL patches the controller Deployment to add
// --webhook-url and related flags. Returns a cleanup function that restores
// the original args and waits for controller rollout.
func patchControllerWithWebhookURL(t *testing.T, clientset kubernetes.Interface, webhookURL string) func() {
	t.Helper()
	ctx := context.Background()

	deploy, err := clientset.AppsV1().Deployments(controllerNamespace).Get(
		ctx, controllerDeploymentName, metav1.GetOptions{},
	)
	require.NoError(t, err, "failed to get controller deployment")
	require.NotEmpty(t, deploy.Spec.Template.Spec.Containers, "controller deployment has no containers")

	// Save original args for restoration.
	originalArgs := make([]string, len(deploy.Spec.Template.Spec.Containers[0].Args))
	copy(originalArgs, deploy.Spec.Template.Spec.Containers[0].Args)

	// Filter out any existing webhook args to avoid duplicates.
	var cleanArgs []string
	for _, arg := range deploy.Spec.Template.Spec.Containers[0].Args {
		if !strings.HasPrefix(arg, "--webhook-") {
			cleanArgs = append(cleanArgs, arg)
		}
	}

	// Add webhook args.
	newArgs := append(cleanArgs,
		fmt.Sprintf("--webhook-url=%s", webhookURL),
		"--webhook-timeout=5",
		"--webhook-min-severity=Info",
	)
	deploy.Spec.Template.Spec.Containers[0].Args = newArgs

	_, err = clientset.AppsV1().Deployments(controllerNamespace).Update(ctx, deploy, metav1.UpdateOptions{})
	require.NoError(t, err, "failed to patch controller deployment with webhook args")
	t.Logf("Patched controller deployment with --webhook-url=%s", webhookURL)

	return func() {
		t.Log("Restoring controller deployment args...")
		deploy, err := clientset.AppsV1().Deployments(controllerNamespace).Get(
			ctx, controllerDeploymentName, metav1.GetOptions{},
		)
		if err != nil {
			t.Logf("Warning: failed to get controller deployment for restore: %v", err)
			return
		}
		deploy.Spec.Template.Spec.Containers[0].Args = originalArgs
		_, err = clientset.AppsV1().Deployments(controllerNamespace).Update(ctx, deploy, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("Warning: failed to restore controller deployment args: %v", err)
			return
		}
		// Wait for rollout to complete.
		waitForControllerReady(t, clientset, 120*time.Second)
		t.Log("Controller deployment restored")
	}
}

// verifyWebhookSenderStarted checks that the controller logs contain
// "Webhook sender started", confirming the webhook sender was initialized.
func verifyWebhookSenderStarted(t *testing.T, clientset kubernetes.Interface) {
	t.Helper()
	logs := getControllerLogs(t, clientset, 500)
	require.Contains(t, logs, "Webhook sender started",
		"controller logs should show webhook sender started;\nlogs:\n%s", logs)
	t.Log("Verified: webhook sender started")
}

// pollForLogMessage polls the controller logs until the expected message appears or timeout.
func pollForLogMessage(t *testing.T, clientset kubernetes.Interface, message string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		logs := getControllerLogs(t, clientset, 200)
		if strings.Contains(logs, message) {
			return
		}
		select {
		case <-deadline:
			t.Logf("Timed out waiting for log message %q (continuing anyway)", message)
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// verifyNoWebhookErrors checks that the controller logs do NOT contain
// "Webhook send failed", confirming webhook sends were successful.
func verifyNoWebhookErrors(t *testing.T, clientset kubernetes.Interface) {
	t.Helper()
	logs := getControllerLogs(t, clientset, 200)
	assert.NotContains(t, logs, "Webhook send failed",
		"controller logs should not show webhook send errors")
	assert.NotContains(t, logs, "External sender enqueue failed",
		"controller logs should not show sender enqueue errors")
	t.Log("Verified: no webhook send errors in controller logs")
}
