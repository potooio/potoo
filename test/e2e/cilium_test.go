//go:build e2e
// +build e2e

// Package e2e contains end-to-end tests for the Cilium adapter and Hubble
// flow drop detection. These tests require Cilium CRDs to be installed in
// the cluster (via make e2e-setup-cilium). Tests skip gracefully if Cilium
// CRDs are absent. Hubble-specific tests additionally require Hubble Relay
// to be running.
package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Cilium GVRs.
var (
	ciliumNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}
	ciliumClusterwideNetworkPolicyGVR = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumclusterwidenetworkpolicies",
	}
)

const (
	// ciliumAnnotationTimeout accounts for: CRD rescan (30s) + informer sync +
	// adapter parse + indexer upsert + debounce (30s) + annotator patch.
	// Use 180s to accommodate parallel test contention on single-node clusters.
	ciliumAnnotationTimeout = 180 * time.Second

	// hubbleFlowDropTimeout is the time to wait for Hubble flow drop correlation
	// to appear in controller logs. Accounts for: Hubble Relay connection +
	// BPF policy propagation + traffic generation + correlator processing.
	hubbleFlowDropTimeout = 240 * time.Second

	// cnpEnforcementWait is the time to wait for a CiliumNetworkPolicy to be
	// enforced by the Cilium agent's BPF dataplane after creation.
	cnpEnforcementWait = 15 * time.Second

	// podReadyTimeout is the time to wait for a pod to reach Running phase.
	podReadyTimeout = 120 * time.Second
)

// requireCiliumInstalled skips the test if Cilium CRDs are not installed.
func requireCiliumInstalled(t *testing.T, dynamicClient dynamic.Interface) {
	t.Helper()
	_, err := dynamicClient.Resource(crdGVR).Get(
		context.Background(), "ciliumnetworkpolicies.cilium.io", metav1.GetOptions{},
	)
	if err != nil {
		t.Skip("Skipping: Cilium CRDs not installed (ciliumnetworkpolicies.cilium.io not found)")
	}
}

// requireHubbleReady skips the test if Hubble Relay is not running.
func requireHubbleReady(t *testing.T, clientset kubernetes.Interface) {
	t.Helper()
	pods, err := clientset.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=hubble-relay",
	})
	if err != nil || len(pods.Items) == 0 {
		t.Skip("Skipping: Hubble Relay pods not found in kube-system")
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			t.Skipf("Skipping: Hubble Relay pod %s is %s, not Running", pod.Name, pod.Status.Phase)
		}
	}
	t.Log("Hubble Relay is running")

	// Verify the controller has Hubble enabled by checking logs for the
	// connection attempt. This avoids testing against a controller that was
	// deployed without --hubble-enabled=true. Use 500 tail lines to avoid
	// missing Hubble log entries on long-running controllers.
	logs := getControllerLogs(t, clientset, 500)
	if !strings.Contains(logs, "hubble") && !strings.Contains(logs, "Hubble") {
		t.Skip("Skipping: controller does not appear to have Hubble enabled (no hubble mentions in logs)")
	}
}

// createCiliumNetworkPolicy creates a CiliumNetworkPolicy in the given namespace.
// Returns a cleanup function.
func createCiliumNetworkPolicy(
	t *testing.T,
	dynamicClient dynamic.Interface,
	namespace, name string,
	spec map[string]interface{},
) func() {
	t.Helper()
	cnp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
	_, err := dynamicClient.Resource(ciliumNetworkPolicyGVR).Namespace(namespace).Create(
		context.Background(), cnp, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create CiliumNetworkPolicy %s/%s", namespace, name)
	t.Logf("Created CiliumNetworkPolicy: %s/%s", namespace, name)

	return func() {
		_ = dynamicClient.Resource(ciliumNetworkPolicyGVR).Namespace(namespace).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createCiliumClusterwideNetworkPolicy creates a CiliumClusterwideNetworkPolicy.
// Returns a cleanup function.
func createCiliumClusterwideNetworkPolicy(
	t *testing.T,
	dynamicClient dynamic.Interface,
	name string,
	spec map[string]interface{},
) func() {
	t.Helper()
	ccnp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": spec,
		},
	}
	_, err := dynamicClient.Resource(ciliumClusterwideNetworkPolicyGVR).Create(
		context.Background(), ccnp, metav1.CreateOptions{},
	)
	require.NoError(t, err, "failed to create CiliumClusterwideNetworkPolicy %s", name)
	t.Logf("Created CiliumClusterwideNetworkPolicy: %s", name)

	return func() {
		_ = dynamicClient.Resource(ciliumClusterwideNetworkPolicyGVR).Delete(
			context.Background(), name, metav1.DeleteOptions{},
		)
	}
}

// createNetworkTestPod creates a pod with curl/wget capability for traffic generation.
// Uses busybox with a sleep command so the pod stays Running.
// Returns a cleanup function.
func createNetworkTestPod(
	t *testing.T,
	clientset kubernetes.Interface,
	namespace, name string,
	labels map[string]string,
) func() {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "nettest",
					Image:   "busybox:1.36",
					Command: []string{"sleep", "3600"},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	_, err := clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create pod %s/%s", namespace, name)
	t.Logf("Created network test pod: %s/%s", namespace, name)

	return func() {
		_ = clientset.CoreV1().Pods(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	}
}

// waitForPodReady waits until a pod is in Running phase with all containers ready.
func waitForPodReady(t *testing.T, clientset kubernetes.Interface, namespace, name string, timeout time.Duration) {
	t.Helper()
	t.Logf("Waiting for pod %s/%s to be ready...", namespace, name)

	waitForCondition(t, timeout, defaultPollInterval, func() (bool, error) {
		pod, err := clientset.CoreV1().Pods(namespace).Get(
			context.Background(), name, metav1.GetOptions{},
		)
		if err != nil {
			return false, nil
		}
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				return false, nil
			}
		}
		return true, nil
	})
	t.Logf("Pod %s/%s is ready", namespace, name)
}

// execInPod runs a command inside a pod using kubectl exec.
// Returns stdout and any error.
func execInPod(t *testing.T, namespace, podName string, command []string) (string, error) {
	t.Helper()
	args := []string{"exec", podName, "-n", namespace, "--"}
	args = append(args, command...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// waitForCNPEnforcement waits for a CiliumNetworkPolicy to be propagated to the
// BPF dataplane by polling its status. Falls back to a fixed wait if status
// polling is not available.
func waitForCNPEnforcement(t *testing.T, dynamicClient dynamic.Interface, namespace, name string) {
	t.Helper()
	t.Logf("Waiting for CiliumNetworkPolicy %s/%s enforcement...", namespace, name)

	deadline := time.Now().Add(cnpEnforcementWait)
	for time.Now().Before(deadline) {
		cnp, err := dynamicClient.Resource(ciliumNetworkPolicyGVR).Namespace(namespace).Get(
			context.Background(), name, metav1.GetOptions{},
		)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		// Check if status.nodes has entries (indicates policy pushed to BPF)
		status, ok, _ := unstructured.NestedMap(cnp.Object, "status")
		if ok && status != nil {
			if nodes, nOk, _ := unstructured.NestedMap(status, "nodes"); nOk && len(nodes) > 0 {
				t.Logf("CiliumNetworkPolicy %s/%s enforced on %d node(s)", namespace, name, len(nodes))
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	// Fallback: if we couldn't confirm via status, wait a fixed amount
	t.Logf("CiliumNetworkPolicy %s/%s status check timed out; proceeding with fixed wait", namespace, name)
	time.Sleep(5 * time.Second)
}

func TestCilium(t *testing.T) {
	t.Parallel()
	requireCiliumInstalled(t, sharedDynamicClient)

	t.Run("PolicyDiscovery", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("allow-ingress-%s", suffix)
		deployName := fmt.Sprintf("cilium-pd-%s", suffix)

		// Create a CiliumNetworkPolicy with L3/L4 ingress rules.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingress": []interface{}{
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"role": "frontend",
							},
						},
					},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"port":     "80",
									"protocol": "TCP",
								},
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-pd")
		defer cleanupTrigger()

		// Wait for the constraint to appear in workload annotations.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})

		// Verify constraint fields.
		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "CiliumNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "NetworkIngress", matched.Type)
		assert.Equal(t, "Warning", matched.Severity)
	})

	t.Run("ClusterwidePolicy", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("ccnp-e2e-%s", suffix)
		deployName := fmt.Sprintf("cilium-cw-%s", suffix)

		// Create a CiliumClusterwideNetworkPolicy with egress rules.
		cleanupCCNP := createCiliumClusterwideNetworkPolicy(t, sharedDynamicClient, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"egress": []interface{}{
				map[string]interface{}{
					"toEntities": []interface{}{"world"},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"port":     "443",
									"protocol": "TCP",
								},
							},
						},
					},
				},
			},
		})
		defer cleanupCCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-cw")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumclusterwidenetworkpolicies" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "CiliumClusterwideNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "NetworkEgress", matched.Type)
		assert.Equal(t, "Warning", matched.Severity)
	})

	t.Run("L7PolicyDetection", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("l7-http-%s", suffix)
		deployName := fmt.Sprintf("cilium-l7-%s", suffix)

		// Create a CiliumNetworkPolicy with L7 HTTP rules.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingress": []interface{}{
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"role": "frontend",
							},
						},
					},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"port":     "80",
									"protocol": "TCP",
								},
							},
							"rules": map[string]interface{}{
								"http": []interface{}{
									map[string]interface{}{
										"method": "GET",
										"path":   "/api/.*",
									},
								},
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-l7")
		defer cleanupTrigger()

		// Wait for the constraint to appear and verify L7 in summary.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "L7 CiliumNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "NetworkIngress", matched.Type)
		assert.Equal(t, "Warning", matched.Severity)
	})

	t.Run("DenyAllPolicy", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("deny-all-%s", suffix)
		deployName := fmt.Sprintf("cilium-da-%s", suffix)

		// Create a CiliumNetworkPolicy with empty spec (deny-all for selected pods).
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-da")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "Deny-all CiliumNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "Critical", matched.Severity)
	})

	t.Run("IngressDenyRules", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("ingress-deny-%s", suffix)
		deployName := fmt.Sprintf("cilium-id-%s", suffix)

		// Create a CiliumNetworkPolicy with explicit ingressDeny rules.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingressDeny": []interface{}{
				map[string]interface{}{
					"fromEntities": []interface{}{"world"},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"port":     "22",
									"protocol": "TCP",
								},
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-id")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "IngressDeny CiliumNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "NetworkIngress", matched.Type)
		assert.Equal(t, "Critical", matched.Severity)
	})

	t.Run("EgressPolicy", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("egress-%s", suffix)
		deployName := fmt.Sprintf("cilium-eg-%s", suffix)

		// Create a CiliumNetworkPolicy with namespace-scoped egress rules.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"egress": []interface{}{
				map[string]interface{}{
					"toEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"k8s:io.kubernetes.pod.namespace": "kube-system",
							},
						},
					},
					"toPorts": []interface{}{
						map[string]interface{}{
							"ports": []interface{}{
								map[string]interface{}{
									"port":     "53",
									"protocol": "UDP",
								},
							},
							"rules": map[string]interface{}{
								"dns": []interface{}{
									map[string]interface{}{
										"matchPattern": "*",
									},
								},
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-eg")
		defer cleanupTrigger()

		// Wait for the constraint to appear.
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})

		var matched *constraintSummary
		for i := range summaries {
			if summaries[i].Name == policyName {
				matched = &summaries[i]
				break
			}
		}
		require.NotNil(t, matched, "Egress CiliumNetworkPolicy constraint not found in annotations")
		assert.Equal(t, "NetworkEgress", matched.Type)
		assert.Equal(t, "Warning", matched.Severity)
	})

	t.Run("HubbleFlowDropDetection", func(t *testing.T) {
		t.Parallel()
		requireHubbleReady(t, sharedClientset)

		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("block-traffic-%s", suffix)
		serverPod := fmt.Sprintf("server-%s", suffix)
		clientPod := fmt.Sprintf("client-%s", suffix)

		serverLabels := map[string]string{
			"app":  "server",
			"role": "backend",
			"test": suffix,
		}
		clientLabels := map[string]string{
			"app":  "client",
			"role": "frontend",
			"test": suffix,
		}

		// Deploy source and destination pods first, wait for them to be ready.
		cleanupServer := createNetworkTestPod(t, sharedClientset, ns, serverPod, serverLabels)
		defer cleanupServer()
		cleanupClient := createNetworkTestPod(t, sharedClientset, ns, clientPod, clientLabels)
		defer cleanupClient()

		waitForPodReady(t, sharedClientset, ns, serverPod, podReadyTimeout)
		waitForPodReady(t, sharedClientset, ns, clientPod, podReadyTimeout)

		// Get the server pod IP for traffic generation.
		server, err := sharedClientset.CoreV1().Pods(ns).Get(
			context.Background(), serverPod, metav1.GetOptions{},
		)
		require.NoError(t, err)
		serverIP := server.Status.PodIP
		require.NotEmpty(t, serverIP, "server pod has no IP")
		t.Logf("Server pod IP: %s", serverIP)

		// Create a CiliumNetworkPolicy that denies all ingress to the server.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app":  "server",
					"role": "backend",
					"test": suffix,
				},
			},
			// No ingress rules = deny all ingress
		})
		defer cleanupCNP()

		// Wait for the policy to be enforced on the BPF dataplane.
		waitForCNPEnforcement(t, sharedDynamicClient, ns, policyName)

		// Generate traffic that should be dropped — attempt to connect from client to server.
		// We try multiple times to ensure Hubble observes at least one drop.
		for i := 0; i < 5; i++ {
			out, execErr := execInPod(t, ns, clientPod, []string{"wget", "-q", "-O", "-", "-T", "2",
				fmt.Sprintf("http://%s:80/", serverIP)})
			t.Logf("Traffic attempt %d: err=%v output=%s", i+1, execErr, strings.TrimSpace(out))
			time.Sleep(2 * time.Second)
		}

		// Check controller logs for flow drop correlation.
		// The controller logs "Flow drop correlated" when Hubble flow drops match constraints.
		t.Log("Checking controller logs for flow drop correlation...")
		waitForCondition(t, hubbleFlowDropTimeout, 5*time.Second, func() (bool, error) {
			logs := getControllerLogs(t, sharedClientset, 200)
			if strings.Contains(logs, "Flow drop correlated") {
				t.Log("Found 'Flow drop correlated' in controller logs")
				return true, nil
			}
			// Re-send traffic to increase chances of detection
			_, _ = execInPod(t, ns, clientPod, []string{"wget", "-q", "-O", "-", "-T", "2",
				fmt.Sprintf("http://%s:80/", serverIP)})
			return false, nil
		})
	})

	t.Run("GracefulDegradation", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("degrade-%s", suffix)
		deployName := fmt.Sprintf("cilium-gd-%s", suffix)

		// Create a CiliumNetworkPolicy — this should work regardless of Hubble status.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingress": []interface{}{
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"access": "allowed",
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Deploy a test workload.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-gd")
		defer cleanupTrigger()

		// Verify constraint discovery works (adapter is independent of Hubble).
		summaries := waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})
		require.NotEmpty(t, summaries, "Cilium constraint should be discoverable regardless of Hubble status")
		t.Log("Cilium policy discovery works independently of Hubble")

		// Verify no Hubble-related panics or fatal errors in controller logs.
		logs := getControllerLogs(t, sharedClientset, 200)
		assert.NotContains(t, logs, "panic", "controller logs should not contain panics")
		assert.NotContains(t, logs, "FATAL", "controller logs should not contain FATAL errors")
	})

	t.Run("DeletionLifecycle", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("lifecycle-%s", suffix)
		deployName := fmt.Sprintf("cilium-dl-%s", suffix)

		// Deploy a test workload first.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		// Create a CiliumNetworkPolicy.
		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingress": []interface{}{
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"trusted": "true",
							},
						},
					},
				},
			},
		})

		// Force the annotator to re-process this namespace.
		cleanupTrigger := createAnnotatorTrigger(t, sharedDynamicClient, ns, "e2e-trigger-cilium-dl")
		defer cleanupTrigger()

		// Wait for it to appear.
		waitForConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})
		t.Log("CiliumNetworkPolicy constraint appeared in annotations")

		// Delete the policy.
		cleanupCNP()
		t.Log("Deleted CiliumNetworkPolicy, waiting for constraint to disappear...")

		// Wait for the constraint to be removed from annotations.
		waitForNoConstraintMatch(t, sharedDynamicClient, ns, deployName,
			ciliumAnnotationTimeout, func(c constraintSummary) bool {
				return c.Source == "ciliumnetworkpolicies" &&
					c.Name == policyName
			})
		t.Log("CiliumNetworkPolicy constraint removed from annotations")
	})

	t.Run("ConstraintReport", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		defer cleanup()

		suffix := rand.String(4)
		policyName := fmt.Sprintf("report-%s", suffix)
		deployName := fmt.Sprintf("cilium-rpt-%s", suffix)

		// Create workload and CiliumNetworkPolicy.
		cleanupDep := createTestDeployment(t, sharedDynamicClient, ns, deployName)
		defer cleanupDep()

		cleanupCNP := createCiliumNetworkPolicy(t, sharedDynamicClient, ns, policyName, map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": deployName,
				},
			},
			"ingress": []interface{}{
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"role": "api",
							},
						},
					},
				},
			},
		})
		defer cleanupCNP()

		// Verify constraint appears in the ConstraintReport.
		waitForCondition(t, ciliumAnnotationTimeout, defaultPollInterval, func() (bool, error) {
			report, err := sharedDynamicClient.Resource(constraintReportGVR).Namespace(ns).Get(
				context.Background(), "constraints", metav1.GetOptions{},
			)
			if err != nil {
				return false, nil
			}
			mr, ok, _ := unstructured.NestedMap(report.Object, "status", "machineReadable")
			if !ok || mr == nil {
				return false, nil
			}
			constraints, ok, _ := unstructured.NestedSlice(mr, "constraints")
			if !ok {
				return false, nil
			}
			for _, raw := range constraints {
				entry, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				if entry["name"] == policyName {
					t.Logf("Found constraint %s in ConstraintReport", policyName)
					return true, nil
				}
			}
			return false, nil
		})
	})
}
