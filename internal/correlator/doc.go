// Package correlator watches Kubernetes Warning events and matches them to
// indexed constraints, producing CorrelatedNotification objects.
//
// # Contract
//
// The Correlator:
//  1. Watches all Events (core/v1) cluster-wide where type=Warning
//  2. For each event, extracts the involvedObject (namespace, name, kind)
//  3. Queries the Indexer for constraints matching that namespace
//  4. Emits CorrelatedNotification to an output channel
//
// # Types
//
//	type CorrelatedNotification struct {
//	    Event      *corev1.Event       // the original K8s event
//	    Constraint types.Constraint    // the matching constraint
//	    Namespace  string              // affected namespace
//	    WorkloadName string            // affected workload name
//	    WorkloadKind string            // affected workload kind (Pod, Deployment, etc.)
//	}
//
// # Rate Limiting
//
// Process at most 100 events/second (token bucket). Drop excess events with a metric.
//
// # Deduplication
//
// Track (eventUID, constraintUID) pairs. Suppress duplicates within 5 minutes.
//
// # Constructor
//
//	func New(indexer *indexer.Indexer, client kubernetes.Interface, logger *zap.Logger) *Correlator
//	func (c *Correlator) Start(ctx context.Context) error  // blocking
//	func (c *Correlator) Notifications() <-chan CorrelatedNotification
package correlator
