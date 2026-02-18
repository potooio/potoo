// Package cilium implements an adapter for parsing Cilium network policies.
//
// Cilium provides advanced network policies for Kubernetes clusters using eBPF.
// This adapter handles:
//   - CiliumNetworkPolicy (namespace-scoped, cilium.io/v2)
//   - CiliumClusterwideNetworkPolicy (cluster-scoped, cilium.io/v2)
//
// # GVRs Handled
//
//   - {Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
//   - {Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}
//
// # Parsing Strategy
//
// CiliumNetworkPolicy has a richer spec than native NetworkPolicy:
//   - endpointSelector: selects pods (like podSelector)
//   - ingress[]: allow ingress rules with fromEndpoints, fromCIDR, fromEntities, toPorts (including L7)
//   - ingressDeny[]: explicit deny ingress rules
//   - egress[]: allow egress rules with toEndpoints, toCIDR, toEntities, toFQDNs, toPorts
//   - egressDeny[]: explicit deny egress rules
//
// Each policy may produce multiple Constraints:
//   - One for ingress rules (ConstraintTypeNetworkIngress)
//   - One for egress rules (ConstraintTypeNetworkEgress)
//
// # Entity Selectors
//
// Cilium allows selecting traffic from/to special entities:
//   - world: external traffic
//   - host: node traffic
//   - cluster: any pod in the cluster
//   - init: init containers
//   - health: health check traffic
//   - unmanaged: non-Cilium pods
//
// # L7 Rules
//
// Cilium supports L7 filtering:
//   - HTTP: paths, methods, headers
//   - DNS: matchName, matchPattern
//   - Kafka: topics, API keys
//
// # Severity Mapping
//
//   - IngressDeny/EgressDeny rules: Critical
//   - Regular ingress/egress rules: Warning
//   - Allow-all or default-allow: Info
package cilium
