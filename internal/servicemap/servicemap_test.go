package servicemap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNew(t *testing.T) {
	sm := New(nil, zap.NewNop())
	require.NotNil(t, sm)
	assert.NotNil(t, sm.services)
	assert.NotNil(t, sm.ipToService)
	assert.NotNil(t, sm.portToServices)
	assert.NotNil(t, sm.endpointToService)
}

func TestUpsertService(t *testing.T) {
	sm := New(nil, zap.NewNop())

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: "monitoring",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.100",
			Selector: map[string]string{
				"app": "prometheus",
			},
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Port:     9090,
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}

	sm.upsertService(svc)

	// Verify service was indexed
	assert.Equal(t, 1, sm.ServiceCount())

	// Verify GetService
	ports := sm.GetService("monitoring", "prometheus")
	require.Len(t, ports, 1)
	assert.Equal(t, "prometheus", ports[0].Name)
	assert.Equal(t, int32(9090), ports[0].Port)
	assert.Equal(t, "http", ports[0].PortName)

	// Verify ClusterIP lookup
	info := sm.ResolvePort("10.0.0.100", 9090)
	require.NotNil(t, info)
	assert.Equal(t, "prometheus", info.Name)
	assert.Equal(t, "monitoring", info.Namespace)

	// Verify port lookup in namespace
	services := sm.ResolvePortInNamespace("monitoring", 9090)
	require.Len(t, services, 1)
	assert.Equal(t, "prometheus", services[0].Name)
}

func TestDeleteService(t *testing.T) {
	sm := New(nil, zap.NewNop())

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus",
			Namespace: "monitoring",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.100",
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 9090,
				},
			},
		},
	}

	sm.upsertService(svc)
	assert.Equal(t, 1, sm.ServiceCount())

	sm.deleteService("monitoring", "prometheus")
	assert.Equal(t, 0, sm.ServiceCount())

	// Verify indexes are cleaned up
	info := sm.ResolvePort("10.0.0.100", 9090)
	assert.Nil(t, info)

	services := sm.ResolvePortInNamespace("monitoring", 9090)
	assert.Empty(t, services)
}

func TestServicesForPod(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Service that selects app=backend
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-service",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "backend",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080},
			},
		},
	}

	// Service that selects app=frontend
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "frontend-service",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "frontend",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
			},
		},
	}

	sm.upsertService(svc1)
	sm.upsertService(svc2)

	// Pod with app=backend should match backend-service
	services := sm.ServicesForPod("production", map[string]string{"app": "backend", "version": "v1"})
	require.Len(t, services, 1)
	assert.Equal(t, "backend-service", services[0].Name)

	// Pod with app=frontend should match frontend-service
	services = sm.ServicesForPod("production", map[string]string{"app": "frontend"})
	require.Len(t, services, 1)
	assert.Equal(t, "frontend-service", services[0].Name)

	// Pod with different labels should not match any
	services = sm.ServicesForPod("production", map[string]string{"app": "other"})
	assert.Empty(t, services)

	// Different namespace should not match
	services = sm.ServicesForPod("staging", map[string]string{"app": "backend"})
	assert.Empty(t, services)
}

func TestUpsertEndpoints(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// First create the service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.50",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080},
			},
		},
	}
	sm.upsertService(svc)

	// Then create endpoints
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.1.10"},
					{IP: "10.0.1.11"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 8080},
				},
			},
		},
	}
	sm.upsertEndpoints(ep)

	// Should be able to resolve endpoint IPs
	info := sm.ResolvePort("10.0.1.10", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)

	info = sm.ResolvePort("10.0.1.11", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)
}

func TestResolvePort_NotFound(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// No services registered
	info := sm.ResolvePort("10.0.0.100", 9090)
	assert.Nil(t, info)
}

func TestMultipleServicesOnSamePort(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Two services on the same port
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-a",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.10",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-b",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.20",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	sm.upsertService(svc1)
	sm.upsertService(svc2)

	// Both should be returned for port lookup
	services := sm.ResolvePortInNamespace("production", 8080)
	require.Len(t, services, 2)

	names := []string{services[0].Name, services[1].Name}
	assert.Contains(t, names, "service-a")
	assert.Contains(t, names, "service-b")

	// But ClusterIP lookup should be specific
	info := sm.ResolvePort("10.0.0.10", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "service-a", info.Name)

	info = sm.ResolvePort("10.0.0.20", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "service-b", info.Name)
}

func TestHeadlessService(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Headless service (ClusterIP = None)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "headless",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{Port: 80},
			},
		},
	}
	sm.upsertService(svc)

	// Should not be in IP index
	info := sm.ResolvePort("None", 80)
	assert.Nil(t, info)

	// But should still be tracked
	assert.Equal(t, 1, sm.ServiceCount())
}

func TestFormatIPPort(t *testing.T) {
	tests := []struct {
		ip       string
		port     int32
		expected string
	}{
		{"10.0.0.1", 80, "10.0.0.1:80"},
		{"192.168.1.100", 8080, "192.168.1.100:8080"},
		{"::1", 443, "::1:443"},
	}

	for _, tt := range tests {
		result := formatIPPort(tt.ip, tt.port)
		assert.Equal(t, tt.expected, result)
	}
}

func TestDeleteEndpoints(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Create a service first
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.50",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080},
			},
		},
	}
	sm.upsertService(svc)

	// Create endpoints
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.1.10"},
					{IP: "10.0.1.11"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 8080},
				},
			},
		},
	}
	sm.upsertEndpoints(ep)

	// Verify endpoints resolve before deletion
	info := sm.ResolvePort("10.0.1.10", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)

	info = sm.ResolvePort("10.0.1.11", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)

	// Delete endpoints
	sm.deleteEndpoints("production", "backend")

	// Endpoint IPs should no longer resolve
	info = sm.ResolvePort("10.0.1.10", 8080)
	assert.Nil(t, info)

	info = sm.ResolvePort("10.0.1.11", 8080)
	assert.Nil(t, info)

	// ClusterIP should still resolve (service not deleted)
	info = sm.ResolvePort("10.0.0.50", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)
}

func TestGetService_NotFound(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Query for service in a namespace that does not exist
	ports := sm.GetService("nonexistent-ns", "some-service")
	assert.Nil(t, ports)

	// Add a service in a different namespace, then query wrong name
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "real-service",
			Namespace: "existing-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
			},
		},
	}
	sm.upsertService(svc)

	// Correct namespace, wrong name
	ports = sm.GetService("existing-ns", "wrong-name")
	assert.Nil(t, ports)

	// Wrong namespace, correct name
	ports = sm.GetService("wrong-ns", "real-service")
	assert.Nil(t, ports)

	// Correct namespace, correct name should work
	ports = sm.GetService("existing-ns", "real-service")
	require.Len(t, ports, 1)
	assert.Equal(t, int32(80), ports[0].Port)
}

func TestResolvePortInNamespace_EmptyNamespace(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Query a namespace that has no services at all
	services := sm.ResolvePortInNamespace("empty-ns", 8080)
	assert.Nil(t, services)

	// Add a service in a different namespace
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-a",
			Namespace: "populated-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}
	sm.upsertService(svc)

	// The empty namespace should still return nil
	services = sm.ResolvePortInNamespace("empty-ns", 8080)
	assert.Nil(t, services)

	// The populated namespace should return the service
	services = sm.ResolvePortInNamespace("populated-ns", 8080)
	require.Len(t, services, 1)
	assert.Equal(t, "service-a", services[0].Name)
}

func TestUpsertService_Update(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Initial service with port 8080
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "evolving-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.200",
			Selector: map[string]string{
				"app": "v1",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	sm.upsertService(svc)

	// Verify initial state
	assert.Equal(t, 1, sm.ServiceCount())
	info := sm.ResolvePort("10.0.0.200", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "evolving-service", info.Name)

	services := sm.ResolvePortInNamespace("default", 8080)
	require.Len(t, services, 1)

	// Update service: change port to 9090 and ClusterIP
	svcUpdated := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "evolving-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.201",
			Selector: map[string]string{
				"app": "v2",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 9090, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	sm.upsertService(svcUpdated)

	// Count should still be 1
	assert.Equal(t, 1, sm.ServiceCount())

	// Old ClusterIP and port should no longer resolve
	info = sm.ResolvePort("10.0.0.200", 8080)
	assert.Nil(t, info)

	// Old port should be gone from namespace index
	services = sm.ResolvePortInNamespace("default", 8080)
	assert.Empty(t, services)

	// New ClusterIP and port should resolve
	info = sm.ResolvePort("10.0.0.201", 9090)
	require.NotNil(t, info)
	assert.Equal(t, "evolving-service", info.Name)

	services = sm.ResolvePortInNamespace("default", 9090)
	require.Len(t, services, 1)
	assert.Equal(t, "evolving-service", services[0].Name)

	// Selector should be updated
	matchingPods := sm.ServicesForPod("default", map[string]string{"app": "v2"})
	require.Len(t, matchingPods, 1)

	oldPods := sm.ServicesForPod("default", map[string]string{"app": "v1"})
	assert.Empty(t, oldPods)
}

func TestDeleteService_NonExistent(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Delete from empty map should not panic
	sm.deleteService("nonexistent-ns", "nonexistent-svc")
	assert.Equal(t, 0, sm.ServiceCount())

	// Add a service, then delete a different one
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "real-service",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 80},
			},
		},
	}
	sm.upsertService(svc)
	assert.Equal(t, 1, sm.ServiceCount())

	// Delete a non-existent service in the same namespace
	sm.deleteService("default", "fake-service")
	assert.Equal(t, 1, sm.ServiceCount())

	// Delete a non-existent service in a different namespace
	sm.deleteService("other-ns", "real-service")
	assert.Equal(t, 1, sm.ServiceCount())

	// The real service should still be there
	ports := sm.GetService("default", "real-service")
	require.Len(t, ports, 1)
}

func TestDeleteService_WithOtherServicesOnSamePort(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Two services on port 8080 in the same namespace
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-a",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.10",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-b",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.20",
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	sm.upsertService(svc1)
	sm.upsertService(svc2)
	assert.Equal(t, 2, sm.ServiceCount())

	// Verify both resolve on the port index
	services := sm.ResolvePortInNamespace("production", 8080)
	require.Len(t, services, 2)

	// Delete service-a; service-b should remain in the port index
	sm.deleteService("production", "service-a")
	assert.Equal(t, 1, sm.ServiceCount())

	services = sm.ResolvePortInNamespace("production", 8080)
	require.Len(t, services, 1)
	assert.Equal(t, "service-b", services[0].Name)

	// ClusterIP for service-a should be gone
	info := sm.ResolvePort("10.0.0.10", 8080)
	assert.Nil(t, info)

	// ClusterIP for service-b should still resolve
	info = sm.ResolvePort("10.0.0.20", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "service-b", info.Name)
}

func TestDeleteEndpoints_NonExistent(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Delete from empty map should not panic
	sm.deleteEndpoints("nonexistent-ns", "nonexistent-ep")
	assert.Equal(t, 0, sm.ServiceCount())

	// Add a service with endpoints, then delete endpoints for a different service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.50",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080},
			},
		},
	}
	sm.upsertService(svc)

	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "production",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.1.10"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 8080},
				},
			},
		},
	}
	sm.upsertEndpoints(ep)

	// Delete endpoints for a different service - should not affect existing
	sm.deleteEndpoints("production", "frontend")
	sm.deleteEndpoints("staging", "backend")

	// Original endpoints should still resolve
	info := sm.ResolvePort("10.0.1.10", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "backend", info.Name)
}

// TestUpsertEndpoints_NoCorrespondingService covers the early-return branch in
// upsertEndpoints when no matching service exists in the map.
func TestUpsertEndpoints_NoCorrespondingService(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Upsert endpoints without a corresponding service
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphan-ep",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.5.1"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 8080},
				},
			},
		},
	}
	sm.upsertEndpoints(ep)

	// Endpoint IP should not resolve because there is no corresponding service
	info := sm.ResolvePort("10.0.5.1", 8080)
	assert.Nil(t, info)
}

// TestDoWatchServices verifies that doWatchServices picks up Service Add, Modify,
// and Delete events from the fake Kubernetes client.
func TestDoWatchServices(t *testing.T) {
	client := fake.NewSimpleClientset()
	sm := New(client, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sm.doWatchServices(ctx)
	}()

	// Give the watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create a service via the fake client
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "watch-svc",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.55",
			Selector: map[string]string{
				"app": "watched",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	_, err := client.CoreV1().Services("test-ns").Create(ctx, svc, metav1.CreateOptions{})
	require.NoError(t, err)

	// Wait for the event to be processed
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 1, sm.ServiceCount())
	info := sm.ResolvePort("10.0.0.55", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "watch-svc", info.Name)

	// Modify the service: change ClusterIP (update)
	svc.Spec.ClusterIP = "10.0.0.56"
	_, err = client.CoreV1().Services("test-ns").Update(ctx, svc, metav1.UpdateOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Old IP should be gone, new IP should resolve
	info = sm.ResolvePort("10.0.0.55", 8080)
	assert.Nil(t, info)

	info = sm.ResolvePort("10.0.0.56", 8080)
	require.NotNil(t, info)
	assert.Equal(t, "watch-svc", info.Name)

	// Delete the service
	err = client.CoreV1().Services("test-ns").Delete(ctx, "watch-svc", metav1.DeleteOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 0, sm.ServiceCount())
	info = sm.ResolvePort("10.0.0.56", 8080)
	assert.Nil(t, info)

	// Cancel context to stop the watcher
	cancel()

	select {
	case watchErr := <-errCh:
		// doWatchServices should return the context error
		assert.ErrorIs(t, watchErr, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("doWatchServices did not return after context cancellation")
	}
}

// TestDoWatchEndpoints verifies that doWatchEndpoints picks up Endpoints Add,
// Modify, and Delete events from the fake Kubernetes client.
func TestDoWatchEndpoints(t *testing.T) {
	client := fake.NewSimpleClientset()
	sm := New(client, zap.NewNop())

	// Pre-create a service so that upsertEndpoints has something to match against
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep-svc",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.70",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 9090, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	sm.upsertService(svc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sm.doWatchEndpoints(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Create endpoints via the fake client
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep-svc",
			Namespace: "test-ns",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.2.10"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 9090},
				},
			},
		},
	}
	_, err := client.CoreV1().Endpoints("test-ns").Create(ctx, ep, metav1.CreateOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Endpoint IP should resolve to the service
	info := sm.ResolvePort("10.0.2.10", 9090)
	require.NotNil(t, info)
	assert.Equal(t, "ep-svc", info.Name)

	// Modify endpoints: add a second address
	ep.Subsets[0].Addresses = append(ep.Subsets[0].Addresses, corev1.EndpointAddress{IP: "10.0.2.11"})
	_, err = client.CoreV1().Endpoints("test-ns").Update(ctx, ep, metav1.UpdateOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	info = sm.ResolvePort("10.0.2.11", 9090)
	require.NotNil(t, info)
	assert.Equal(t, "ep-svc", info.Name)

	// Delete endpoints
	err = client.CoreV1().Endpoints("test-ns").Delete(ctx, "ep-svc", metav1.DeleteOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Endpoint IPs should no longer resolve
	info = sm.ResolvePort("10.0.2.10", 9090)
	assert.Nil(t, info)
	info = sm.ResolvePort("10.0.2.11", 9090)
	assert.Nil(t, info)

	cancel()

	select {
	case watchErr := <-errCh:
		assert.ErrorIs(t, watchErr, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("doWatchEndpoints did not return after context cancellation")
	}
}

// TestStart verifies that Start runs both watchers and stops cleanly when the
// context is cancelled.
func TestStart(t *testing.T) {
	client := fake.NewSimpleClientset()
	sm := New(client, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sm.Start(ctx)
	}()

	// Give watchers time to start
	time.Sleep(150 * time.Millisecond)

	// Create a service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "start-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.80",
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	_, err := client.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 1, sm.ServiceCount())
	info := sm.ResolvePort("10.0.0.80", 80)
	require.NotNil(t, info)
	assert.Equal(t, "start-svc", info.Name)

	// Create endpoints for the service
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "start-svc",
			Namespace: "default",
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "10.0.3.10"},
				},
				Ports: []corev1.EndpointPort{
					{Name: "http", Port: 80},
				},
			},
		},
	}
	_, err = client.CoreV1().Endpoints("default").Create(ctx, ep, metav1.CreateOptions{})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	info = sm.ResolvePort("10.0.3.10", 80)
	require.NotNil(t, info)
	assert.Equal(t, "start-svc", info.Name)

	// Cancel context and wait for Start to return
	cancel()

	select {
	case startErr := <-errCh:
		assert.NoError(t, startErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// TestServicesForPod_MultipleSelectorsMatch verifies that ServicesForPod returns
// services from multiple services whose selectors match the pod labels.
func TestServicesForPod_MultipleSelectorsMatch(t *testing.T) {
	sm := New(nil, zap.NewNop())

	// Service selecting app=api
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api"},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080},
			},
		},
	}
	// Service selecting app=api, tier=internal (subset of pod labels)
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-internal",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api", "tier": "internal"},
			Ports: []corev1.ServicePort{
				{Name: "grpc", Port: 9090},
			},
		},
	}
	// Service with no selector
	svc3 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 443},
			},
		},
	}

	sm.upsertService(svc1)
	sm.upsertService(svc2)
	sm.upsertService(svc3)

	// Pod with app=api, tier=internal should match both svc1 and svc2
	services := sm.ServicesForPod("default", map[string]string{
		"app":  "api",
		"tier": "internal",
	})
	assert.Len(t, services, 2)

	names := make([]string, len(services))
	for i, s := range services {
		names[i] = s.Name
	}
	assert.Contains(t, names, "api-svc")
	assert.Contains(t, names, "api-internal")

	// Pod with only app=api should match svc1 only (not svc2 which also requires tier=internal)
	services = sm.ServicesForPod("default", map[string]string{"app": "api"})
	require.Len(t, services, 1)
	assert.Equal(t, "api-svc", services[0].Name)

	// Service with no selector should never match any pod
	services = sm.ServicesForPod("default", map[string]string{"everything": "matches"})
	assert.Empty(t, services)
}
