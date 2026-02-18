//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Shared clients initialized once in TestMain; goroutine-safe.
var (
	sharedClientset     kubernetes.Interface
	sharedDynamicClient dynamic.Interface
)

// TestMain initializes shared Kubernetes clients and waits for the controller
// to become ready before running any tests. This replaces the testify suite's
// SetupSuite/TearDownSuite lifecycle with Go-idiomatic TestMain + t.Parallel().
func TestMain(m *testing.M) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load kubeconfig: %v\n", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create kubernetes clientset: %v\n", err)
		os.Exit(1)
	}
	sharedClientset = clientset

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create dynamic client: %v\n", err)
		os.Exit(1)
	}
	sharedDynamicClient = dynClient

	// Wait for controller readiness before running tests.
	deadline := time.Now().Add(120 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		deploy, err := clientset.AppsV1().Deployments(controllerNamespace).Get(
			context.Background(), controllerDeploymentName, metav1.GetOptions{},
		)
		if err == nil && deploy.Status.ReadyReplicas > 0 {
			ready = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !ready {
		fmt.Fprintf(os.Stderr, "controller deployment %s/%s not ready after 120s\n",
			controllerNamespace, controllerDeploymentName)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// TestSmoke runs basic health-check tests that verify the controller
// deployment and test infrastructure are functional.
func TestSmoke(t *testing.T) {
	t.Parallel()

	t.Run("ControllerHealthy", func(t *testing.T) {
		t.Parallel()
		deploy, err := sharedClientset.AppsV1().Deployments(controllerNamespace).Get(
			context.Background(), controllerDeploymentName, metav1.GetOptions{},
		)
		require.NoError(t, err, "failed to get controller deployment")
		require.Greater(t, deploy.Status.ReadyReplicas, int32(0),
			"controller has no ready replicas")
		t.Logf("Controller is healthy: %d ready replicas", deploy.Status.ReadyReplicas)
	})

	t.Run("ControllerLogs", func(t *testing.T) {
		t.Parallel()
		logs := getControllerLogs(t, sharedClientset, 10)
		require.NotEmpty(t, logs, "controller produced no logs")
		t.Logf("Controller log tail:\n%s", logs)
	})

	t.Run("NamespaceCreated", func(t *testing.T) {
		t.Parallel()
		ns, cleanup := createTestNamespace(t, sharedClientset)
		t.Cleanup(cleanup)

		nsObj, err := sharedClientset.CoreV1().Namespaces().Get(
			context.Background(), ns, metav1.GetOptions{},
		)
		require.NoError(t, err, "failed to get test namespace")
		require.Equal(t, "true", nsObj.Labels[e2eLabel], "test namespace missing e2e label")
	})
}
