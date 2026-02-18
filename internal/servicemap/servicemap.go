package servicemap

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// ServiceInfo contains information about a service and a specific port.
type ServiceInfo struct {
	Name      string
	Namespace string
	Port      int32
	PortName  string
	Protocol  string
	ClusterIP string
}

// EndpointInfo contains information about a service endpoint.
type EndpointInfo struct {
	IP       string
	Port     int32
	PortName string
	PodName  string
	NodeName string
}

// ServiceMap maintains a mapping of Kubernetes services to their ports and endpoints.
type ServiceMap struct {
	logger *zap.Logger
	client kubernetes.Interface

	mu sync.RWMutex

	// Services by namespace/name
	services map[string]map[string]*serviceEntry

	// ClusterIP → service lookup
	ipToService map[string]*ServiceInfo

	// Port → service mappings per namespace
	// namespace → port → list of services exposing that port
	portToServices map[string]map[int32][]*ServiceInfo

	// Pod endpoint IPs → service
	endpointToService map[string]*ServiceInfo
}

// serviceEntry holds the parsed service data.
type serviceEntry struct {
	Name      string
	Namespace string
	ClusterIP string
	Selector  labels.Selector
	Ports     []ServiceInfo
}

// New creates a new ServiceMap.
func New(client kubernetes.Interface, logger *zap.Logger) *ServiceMap {
	return &ServiceMap{
		logger:            logger.Named("servicemap"),
		client:            client,
		services:          make(map[string]map[string]*serviceEntry),
		ipToService:       make(map[string]*ServiceInfo),
		portToServices:    make(map[string]map[int32][]*ServiceInfo),
		endpointToService: make(map[string]*ServiceInfo),
	}
}

// Start begins watching Services and Endpoints. Blocks until context is cancelled.
func (sm *ServiceMap) Start(ctx context.Context) error {
	sm.logger.Info("Starting service map")

	// Start both watchers in goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		sm.watchServices(ctx)
	}()

	go func() {
		defer wg.Done()
		sm.watchEndpoints(ctx)
	}()

	wg.Wait()
	sm.logger.Info("Service map stopped")
	return nil
}

// watchServices watches Service resources and updates the map.
func (sm *ServiceMap) watchServices(ctx context.Context) {
	for {
		if err := sm.doWatchServices(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			sm.logger.Error("Service watch failed, retrying", zap.Error(err))
			time.Sleep(5 * time.Second)
		}
	}
}

func (sm *ServiceMap) doWatchServices(ctx context.Context) error {
	watcher, err := sm.client.CoreV1().Services("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil // Watch closed, will be restarted
			}
			svc, ok := event.Object.(*corev1.Service)
			if !ok {
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				sm.upsertService(svc)
			case watch.Deleted:
				sm.deleteService(svc.Namespace, svc.Name)
			}
		}
	}
}

// watchEndpoints watches Endpoints resources and updates the map.
func (sm *ServiceMap) watchEndpoints(ctx context.Context) {
	for {
		if err := sm.doWatchEndpoints(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			sm.logger.Error("Endpoints watch failed, retrying", zap.Error(err))
			time.Sleep(5 * time.Second)
		}
	}
}

func (sm *ServiceMap) doWatchEndpoints(ctx context.Context) error {
	watcher, err := sm.client.CoreV1().Endpoints("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return nil
			}
			ep, ok := event.Object.(*corev1.Endpoints)
			if !ok {
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				sm.upsertEndpoints(ep)
			case watch.Deleted:
				sm.deleteEndpoints(ep.Namespace, ep.Name)
			}
		}
	}
}

// upsertService adds or updates a service in the map.
func (sm *ServiceMap) upsertService(svc *corev1.Service) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	ns := svc.Namespace
	name := svc.Name

	// Create namespace map if needed
	if sm.services[ns] == nil {
		sm.services[ns] = make(map[string]*serviceEntry)
	}
	if sm.portToServices[ns] == nil {
		sm.portToServices[ns] = make(map[int32][]*ServiceInfo)
	}

	// Remove old entries
	if old := sm.services[ns][name]; old != nil {
		sm.removeServiceFromIndexes(old)
	}

	// Parse selector
	var selector labels.Selector
	if len(svc.Spec.Selector) > 0 {
		selector = labels.SelectorFromSet(svc.Spec.Selector)
	}

	// Build service entry
	entry := &serviceEntry{
		Name:      name,
		Namespace: ns,
		ClusterIP: svc.Spec.ClusterIP,
		Selector:  selector,
		Ports:     make([]ServiceInfo, 0, len(svc.Spec.Ports)),
	}

	for _, port := range svc.Spec.Ports {
		info := ServiceInfo{
			Name:      name,
			Namespace: ns,
			Port:      port.Port,
			PortName:  port.Name,
			Protocol:  string(port.Protocol),
			ClusterIP: svc.Spec.ClusterIP,
		}
		entry.Ports = append(entry.Ports, info)

		// Index by port
		sm.portToServices[ns][port.Port] = append(sm.portToServices[ns][port.Port], &info)

		// Index by ClusterIP:port
		if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
			key := formatIPPort(svc.Spec.ClusterIP, port.Port)
			sm.ipToService[key] = &info
		}
	}

	sm.services[ns][name] = entry
}

// deleteService removes a service from the map.
func (sm *ServiceMap) deleteService(namespace, name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.services[namespace] == nil {
		return
	}
	if entry := sm.services[namespace][name]; entry != nil {
		sm.removeServiceFromIndexes(entry)
		delete(sm.services[namespace], name)
	}
}

// removeServiceFromIndexes removes a service from secondary indexes.
func (sm *ServiceMap) removeServiceFromIndexes(entry *serviceEntry) {
	ns := entry.Namespace

	for _, port := range entry.Ports {
		// Remove from port index
		if portList := sm.portToServices[ns][port.Port]; portList != nil {
			var filtered []*ServiceInfo
			for _, s := range portList {
				if s.Name != entry.Name {
					filtered = append(filtered, s)
				}
			}
			if len(filtered) > 0 {
				sm.portToServices[ns][port.Port] = filtered
			} else {
				delete(sm.portToServices[ns], port.Port)
			}
		}

		// Remove from IP index
		if entry.ClusterIP != "" && entry.ClusterIP != "None" {
			key := formatIPPort(entry.ClusterIP, port.Port)
			delete(sm.ipToService, key)
		}
	}
}

// upsertEndpoints adds or updates endpoints in the map.
func (sm *ServiceMap) upsertEndpoints(ep *corev1.Endpoints) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	ns := ep.Namespace
	name := ep.Name

	// Get the corresponding service
	var svc *serviceEntry
	if sm.services[ns] != nil {
		svc = sm.services[ns][name]
	}
	if svc == nil {
		return // No corresponding service
	}

	// Build endpoint IP → service mapping
	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			for _, port := range subset.Ports {
				// Find matching service port
				for i := range svc.Ports {
					if svc.Ports[i].PortName == port.Name || svc.Ports[i].Port == port.Port {
						key := formatIPPort(addr.IP, port.Port)
						sm.endpointToService[key] = &svc.Ports[i]
					}
				}
			}
		}
	}
}

// deleteEndpoints removes endpoints from the map.
func (sm *ServiceMap) deleteEndpoints(namespace, name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Remove all endpoint IPs for this service
	// This is O(n) but typically endpoints are not deleted often
	toDelete := make([]string, 0)
	for key, info := range sm.endpointToService {
		if info.Namespace == namespace && info.Name == name {
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		delete(sm.endpointToService, key)
	}
}

// ResolvePort looks up a service by IP and port.
// Returns nil if no matching service is found.
func (sm *ServiceMap) ResolvePort(ip string, port int32) *ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	key := formatIPPort(ip, port)

	// Try ClusterIP lookup first
	if info := sm.ipToService[key]; info != nil {
		return info
	}

	// Try endpoint lookup
	if info := sm.endpointToService[key]; info != nil {
		return info
	}

	return nil
}

// ResolvePortInNamespace looks up a service by port in a specific namespace.
// Returns nil if no matching service is found.
func (sm *ServiceMap) ResolvePortInNamespace(namespace string, port int32) []*ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.portToServices[namespace] == nil {
		return nil
	}
	return sm.portToServices[namespace][port]
}

// ServicesForPod returns all services that select a pod with the given labels.
func (sm *ServiceMap) ServicesForPod(namespace string, podLabels map[string]string) []*ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.services[namespace] == nil {
		return nil
	}

	var result []*ServiceInfo
	labelSet := labels.Set(podLabels)

	for _, entry := range sm.services[namespace] {
		if entry.Selector != nil && entry.Selector.Matches(labelSet) {
			for i := range entry.Ports {
				result = append(result, &entry.Ports[i])
			}
		}
	}

	return result
}

// GetService returns the service info for a given namespace/name.
func (sm *ServiceMap) GetService(namespace, name string) []ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.services[namespace] == nil {
		return nil
	}
	if entry := sm.services[namespace][name]; entry != nil {
		return entry.Ports
	}
	return nil
}

// ServiceCount returns the total number of tracked services.
func (sm *ServiceMap) ServiceCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, nsServices := range sm.services {
		count += len(nsServices)
	}
	return count
}

// formatIPPort creates a lookup key from IP and port.
func formatIPPort(ip string, port int32) string {
	return fmt.Sprintf("%s:%d", ip, port)
}
