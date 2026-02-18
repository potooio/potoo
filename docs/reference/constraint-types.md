---
layout: default
title: Constraint Types
parent: Reference
nav_order: 1
---

# Constraint Types
{: .no_toc }

Reference for all constraint type classifications.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Potoo normalizes all policy types into a common constraint model. Each constraint has a `type` field that classifies what kind of restriction it represents.

---

## NetworkIngress

Inbound network traffic restrictions.

### Meaning
Controls which traffic can **reach** workloads in the namespace.

### Sources
- Kubernetes NetworkPolicy (with `policyTypes: ["Ingress"]`)
- CiliumNetworkPolicy (ingress rules)
- CiliumClusterwideNetworkPolicy (ingress rules)
- Istio AuthorizationPolicy (ALLOW/DENY actions)

### Effects
- `deny` - Traffic is blocked by default
- `restrict` - Traffic allowed only from specific sources

### Common Errors
```
connection refused
connection reset by peer
no route to host (from external caller)
```

### Example Constraint
```yaml
name: frontend-only
type: NetworkIngress
severity: Critical
effect: deny
summary: "Only allows ingress from frontend pods"
tags: [network, ingress, pod-selector]
```

### Remediation Patterns
1. Request exception from platform team
2. Add caller to allowed source list
3. Use service mesh for internal traffic

---

## NetworkEgress

Outbound network traffic restrictions.

### Meaning
Controls which traffic workloads can **send** from the namespace.

### Sources
- Kubernetes NetworkPolicy (with `policyTypes: ["Egress"]`)
- CiliumNetworkPolicy (egress rules)
- CiliumClusterwideNetworkPolicy (egress rules)
- Istio AuthorizationPolicy (egress rules)

### Effects
- `deny` - All egress blocked by default
- `restrict` - Egress allowed only to specific destinations/ports

### Common Errors
```
connection timed out
dial tcp: i/o timeout
no route to host
connection refused (to external service)
```

### Example Constraint
```yaml
name: restrict-egress
type: NetworkEgress
severity: Critical
effect: deny
summary: "Egress restricted to ports 443, 8443"
tags: [network, egress, port-restriction]
```

### Remediation Patterns
1. Request egress exception for specific destination
2. Route through approved egress proxy
3. Use internal service instead of external

---

## Admission

Admission controller rejections.

### Meaning
Policies that accept or reject Kubernetes resource creation/modification.

### Sources
- ValidatingWebhookConfiguration
- MutatingWebhookConfiguration (when mutation fails)
- OPA Gatekeeper Constraints
- Kyverno ClusterPolicy/Policy
- Custom admission webhooks

### Effects
- `deny` - Resource rejected
- `warn` - Warning issued but allowed
- `audit` - Logged but allowed

### Common Errors
```
admission webhook "xxx" denied the request
Error from server (Forbidden): xxx is not allowed
denied by policy "xxx"
validation failed: xxx
```

### Example Constraint
```yaml
name: require-resource-limits
type: Admission
severity: Critical
effect: deny
summary: "Containers must have resource limits"
tags: [admission, resources, gatekeeper]
```

### Remediation Patterns
1. Modify resource to comply with policy
2. Add required labels/annotations
3. Set resource limits/requests
4. Request policy exception

---

## ResourceLimit

Resource quota and limit restrictions.

### Meaning
Controls resource consumption within a namespace.

### Sources
- ResourceQuota
- LimitRange

### Effects
- `limit` - Consumption capped at threshold
- `restrict` - Specific resource types restricted

### Common Errors
```
exceeded quota: requested cpu 2, limit 1
forbidden: exceeded quota
unable to schedule pod: insufficient cpu
```

### Example Constraint
```yaml
name: compute-quota
type: ResourceLimit
severity: Warning
effect: limit
summary: "CPU usage at 78% of quota"
metrics:
  cpu:
    hard: "4"
    used: "3.12"
    percentUsed: 78.0
tags: [quota, cpu, memory]
```

### Remediation Patterns
1. Reduce resource requests
2. Request quota increase
3. Clean up unused resources
4. Optimize application resource usage

---

## MeshPolicy

Service mesh authorization policies.

### Meaning
Controls service-to-service communication within a service mesh.

### Sources
- Istio AuthorizationPolicy
- Istio PeerAuthentication
- Linkerd ServerAuthorization

### Effects
- `deny` - Request rejected at mesh layer
- `restrict` - Only specific identities allowed
- `require` - Mutual TLS required

### Common Errors
```
RBAC: access denied
upstream connect error
403 Forbidden (from Envoy)
connection reset (mTLS failure)
```

### Example Constraint
```yaml
name: require-mtls
type: MeshPolicy
severity: Critical
effect: require
summary: "mTLS required for all pod-to-pod traffic"
tags: [mesh, istio, mtls]
```

### Remediation Patterns
1. Enable Istio sidecar injection
2. Configure correct ServiceAccount
3. Add workload to allowed principals
4. Check mTLS configuration

---

## MissingResource

Expected companion resources not found.

### Meaning
A resource that should exist (based on annotations or conventions) is missing.

### Sources
- Missing ServiceMonitor/PodMonitor (for workloads with a `metrics` or `http-metrics` port)
- Missing VirtualService/DestinationRule (for workloads with Istio sidecar)
- Missing PeerAuthentication (for namespaces with Istio injection enabled)
- Missing ClusterIssuer/Issuer (for workloads with cert-manager annotations)

See [Missing Resource Detection](/docs/controller/missing-resources/) for the full list of built-in rules and their detection logic.

### Effects
- `missing` - Required resource doesn't exist

### Common Errors
```
(No error - resource silently not working)
Metrics not appearing in Prometheus
Traffic not being routed through mesh
```

### Example Constraint
```yaml
name: missing-prometheus-monitor-api-server
type: MissingResource
severity: Warning
effect: missing
summary: "Workload exposes a metrics port but has no ServiceMonitor or PodMonitor"
tags: [prometheus, monitoring, missing-resource]
```

### Remediation Patterns
1. Create the missing resource
2. Remove the annotation if not needed
3. Use provided YAML template

---

## Unknown

Unclassified constraint from generic adapter.

### Meaning
A policy from a custom CRD registered via ConstraintProfile, parsed by the generic adapter.

### Sources
- Any CRD registered with `adapter: generic`
- Unrecognized policy CRDs

### Effects
- Varies by source

### Example Constraint
```yaml
name: custom-policy-1
type: Unknown
severity: Info
effect: unknown
summary: "Custom policy (see source for details)"
tags: []
```

### Remediation Patterns
1. Consult documentation for the custom policy type
2. Contact platform team

---

## Type Distribution

Typical distribution in a production cluster:

| Type | Typical Count | Notes |
|------|---------------|-------|
| NetworkEgress | 30-50% | Most common restriction |
| NetworkIngress | 10-20% | Default deny ingress |
| Admission | 15-25% | Compliance policies |
| ResourceLimit | 10-20% | Quotas per namespace |
| MeshPolicy | 5-15% | If service mesh enabled |
| MissingResource | 5-10% | Monitoring gaps |
| Unknown | 1-5% | Custom policies |

---

## Filtering by Type

### CLI
```bash
potoo query -n my-namespace --type NetworkEgress
```

### MCP Tool
```json
{
  "tool": "potoo_query",
  "params": {
    "namespace": "my-namespace",
    "constraint_type": "NetworkEgress"
  }
}
```

### kubectl
```bash
kubectl get cr constraints -n my-namespace -o json | \
  jq '.status.constraints[] | select(.type == "NetworkEgress")'
```
