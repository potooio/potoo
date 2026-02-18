// Package servicemap maintains a mapping of Kubernetes Service names to their
// associated ports and endpoints. This enables semantic notifications that
// reference service names rather than raw port numbers.
//
// # Overview
//
// When a flow drop occurs, we see source/destination IPs and ports. The service
// map allows us to resolve "10.0.2.5:9090" to "prometheus-server.monitoring:9090",
// providing developers with more meaningful context.
//
// # Data Model
//
// The service map maintains:
//   - Service → Port mappings: which named ports a service exposes
//   - Pod → Service mappings: which services select a given pod (via label matching)
//   - IP → Service mappings: reverse lookup from ClusterIP to service name
//
// # Usage
//
//	sm := servicemap.New(client, zap.NewNop())
//	go sm.Start(ctx)
//
//	// Resolve a port to a service name
//	svc := sm.ResolvePort("production", "10.0.2.5", 9090)
//	if svc != nil {
//	    fmt.Printf("Access to %s.%s:%d blocked\n", svc.Name, svc.Namespace, svc.Port)
//	}
//
//	// Find services that select a pod
//	services := sm.ServicesForPod("production", map[string]string{"app": "backend"})
//
// # Synchronization
//
// The service map uses informers to watch Service and Endpoints objects.
// Updates are applied atomically and queries are lock-free reads against
// immutable snapshots.
package servicemap
