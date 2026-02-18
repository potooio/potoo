// Package hubble provides a client for connecting to Hubble Relay and observing
// network flow drops.
//
// # Overview
//
// Hubble is Cilium's observability layer that provides real-time visibility into
// network traffic. This package connects to Hubble Relay via gRPC and subscribes
// to flow events, specifically filtering for dropped flows.
//
// # Usage
//
// The Client provides a stream of FlowDrop events that can be consumed by the
// correlation engine to match traffic drops to constraints:
//
//	client, err := hubble.NewClient(ctx, hubble.ClientOptions{
//	    RelayAddress: "hubble-relay.kube-system.svc:4245",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	dropChan := client.DroppedFlows()
//	for drop := range dropChan {
//	    // Process the drop event
//	    fmt.Printf("Flow drop: %s -> %s (reason: %s)\n",
//	        drop.Source.PodName, drop.Destination.PodName, drop.DropReason)
//	}
//
// # Graceful Degradation
//
// The client handles disconnections gracefully with exponential backoff reconnection.
// If Hubble Relay is unavailable, the client will continue attempting to reconnect
// while exposing metrics about its connection state.
//
// # Privacy Considerations
//
// Flow drop events contain cross-namespace pod identities. The correlation engine
// is responsible for privacy scoping before notifications are dispatched.
//
// # Metrics
//
// The client exposes the following Prometheus metrics:
//   - potoo_hubble_connected (gauge): 1 if connected, 0 if disconnected
//   - potoo_hubble_flow_drops_total (counter, labels: namespace): Total flow drops observed
//   - potoo_hubble_reconnects_total (counter): Total reconnection attempts
package hubble
