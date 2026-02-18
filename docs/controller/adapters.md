---
layout: default
title: Adapters
parent: Controller
nav_order: 2
---

# Adapters
{: .no_toc }

Adapters parse policy engine CRDs into normalized constraints.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Each policy engine has a different CRD schema. Adapters normalize them into a common `Constraint` model:

```
NetworkPolicy        ─┐
CiliumNetworkPolicy  ─┼─▶ Adapter ─▶ Constraint{Type, Severity, Effect, ...}
K8sRequiredLabels    ─┘
```

---

## Built-in Adapters

### networkpolicy

Parses Kubernetes NetworkPolicy resources.

**Watched Resources:**
- `networking.k8s.io/v1/NetworkPolicy`

**Constraint Types Generated:**
- `NetworkIngress` - When `spec.policyTypes` includes "Ingress"
- `NetworkEgress` - When `spec.policyTypes` includes "Egress"

**Example Constraint:**
```yaml
Name: restrict-egress
Type: NetworkEgress
Severity: Critical
Effect: deny
Summary: "Egress restricted to ports 443, 8443"
Tags: [network, egress, port-restriction]
```

---

### resourcequota

Parses ResourceQuota and LimitRange resources.

**Watched Resources:**
- `v1/ResourceQuota`
- `v1/LimitRange`

**Constraint Types Generated:**
- `ResourceLimit`

**Metrics Extracted:**
- CPU usage percentage
- Memory usage percentage
- Storage usage percentage
- Pod count

**Example Constraint:**
```yaml
Name: compute-quota
Type: ResourceLimit
Severity: Warning
Effect: limit
Summary: "CPU usage at 78% of quota"
Details:
  resources:
    cpu:
      hard: "4"
      used: "3.12"
      percent: 78
    memory:
      hard: "8Gi"
      used: "6Gi"
      percent: 75
```

---

### webhook

Parses admission webhook configurations.

**Watched Resources:**
- `admissionregistration.k8s.io/v1/ValidatingWebhookConfiguration`
- `admissionregistration.k8s.io/v1/MutatingWebhookConfiguration`

**Constraint Types Generated:**
- `Admission`

**Example Constraint:**
```yaml
Name: require-labels
Type: Admission
Severity: Critical
Effect: deny
Summary: "ValidatingWebhook may reject pods"
```

---

### cilium

Parses Cilium network policies. Works in two modes:

- **CRD-only mode:** When Cilium CRDs are applied without the Cilium CNI (e.g., GitOps pre-staging), the adapter discovers and parses policies but they are not enforced by a dataplane. Potoo still reports the constraints so developers know what will apply when Cilium is active.
- **CNI mode:** When Cilium is the cluster CNI, policies are actively enforced. If Hubble is enabled, Potoo can also stream flow drops for real-time correlation (see [Hubble Integration](#hubble-integration) below).

**Watched Resources:**
- `cilium.io/v2/CiliumNetworkPolicy`
- `cilium.io/v2/CiliumClusterwideNetworkPolicy`

**Constraint Types Generated:**
- `NetworkIngress`
- `NetworkEgress`

**Example Constraint:**
```yaml
Name: allow-dns-only
Type: NetworkEgress
Severity: Critical
Effect: deny
Summary: "Egress allowed only to kube-dns"
Tags: [network, egress, cilium, dns-only]
```

#### Hubble Integration

When Cilium is deployed with Hubble Relay enabled, Potoo can connect to Hubble's gRPC endpoint and stream `verdict=DROPPED` flows. Dropped flows are correlated with CiliumNetworkPolicy constraints to provide real-time "this deployment's traffic was just blocked by policy X" notifications.

Hubble integration is optional and configured separately from the Cilium adapter:

```yaml
hubble:
  enabled: true
  address: "hubble-relay.kube-system.svc:4245"
```

If Hubble Relay is unavailable, the Cilium adapter continues to function normally — only the real-time flow drop correlation is disabled.

---

### gatekeeper

Parses OPA Gatekeeper constraints.

**Watched Resources:**
- All CRDs created from ConstraintTemplates
- Detected by `constraints.gatekeeper.sh` API group

**Constraint Types Generated:**
- `Admission`

**Example Constraint:**
```yaml
Name: k8srequiredlabels-must-have-team
Type: Admission
Severity: Critical
Effect: deny
Summary: "Gatekeeper: pods must have 'team' label"
Tags: [admission, gatekeeper, labels]
```

---

### kyverno

Parses Kyverno policies.

**Watched Resources:**
- `kyverno.io/v1/ClusterPolicy`
- `kyverno.io/v1/Policy`

**Constraint Types Generated:**
- `Admission`

**Example Constraint:**
```yaml
Name: require-resource-limits
Type: Admission
Severity: Critical
Effect: deny
Summary: "Kyverno: containers must have resource limits"
Tags: [admission, kyverno, resources]
```

---

### istio

Parses Istio security and networking policies into MeshPolicy constraints.
Supports AuthorizationPolicy, PeerAuthentication, and Sidecar resources.
Requires Istio v1 API (Istio 1.18+).

{: .note }
**CRDs-only mode:** The Istio adapter does not require istiod or the Istio control plane. It parses Istio CRD objects directly via `unstructured.Unstructured`, so it works in clusters where Istio CRDs are applied without a running control plane (e.g., GitOps pre-staging, CRD-only testing). The [missing resource detection](/docs/controller/missing-resources/#istio-mtls) rule separately checks for PeerAuthentication when `istio-injection=enabled` is set.

**Watched Resources:**
- `security.istio.io/v1/authorizationpolicies`
- `security.istio.io/v1/peerauthentications`
- `networking.istio.io/v1/sidecars`

**Constraint Types Generated:**
- `MeshPolicy`

**Severity Mapping:**

| Resource | Condition | Severity |
|----------|-----------|----------|
| AuthorizationPolicy | action=DENY | Critical |
| AuthorizationPolicy | action=ALLOW or CUSTOM | Warning |
| PeerAuthentication | mode=STRICT | Warning |
| PeerAuthentication | mode=PERMISSIVE or DISABLE | Info |
| Sidecar | any | Info |

**Example Constraints:**

AuthorizationPolicy (DENY):
```yaml
Name: deny-external
Type: MeshPolicy
Severity: Critical
Effect: deny
Summary: "AuthorizationPolicy \"deny-external\" denies traffic from namespace/untrusted"
Tags: [mesh, istio, authorization]
```

PeerAuthentication (STRICT):
```yaml
Name: strict-mtls
Type: MeshPolicy
Severity: Warning
Effect: require
Summary: "PeerAuthentication \"strict-mtls\": mTLS STRICT (workload scope)"
Tags: [mesh, istio, mtls]
```

Sidecar (egress restriction):
```yaml
Name: restrict-egress
Type: MeshPolicy
Severity: Info
Effect: restrict
Summary: "Sidecar \"restrict-egress\" restricts egress to ./* , istio-system/*"
Tags: [mesh, istio, sidecar]
```

---

### generic

Fallback adapter for unknown CRDs registered via ConstraintProfile.

**Watched Resources:**
- Any CRD registered in a ConstraintProfile with `adapter: generic`

**Constraint Types Generated:**
- `Unknown`

---

## Enabling Adapters

### Auto-Detection (Default)

```yaml
adapters:
  cilium:
    enabled: auto  # Enable if CRDs exist
```

The adapter enables automatically when:
1. The relevant CRDs are installed
2. The controller has RBAC access

### Force Enable

```yaml
adapters:
  cilium:
    enabled: enabled  # Always enable
```

The controller will fail to start if CRDs are missing.

### Disable

```yaml
adapters:
  gatekeeper:
    enabled: disabled  # Never enable
```

Useful when you have CRDs installed but don't want Potoo to watch them.

---

## Custom Adapters via ConstraintProfile

Register custom policy CRDs using the ConstraintProfile CRD:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-network-policy
spec:
  gvr:
    group: custom.example.com
    version: v1
    resource: networkrules
  adapter: generic  # Use generic adapter
  enabled: true
  severity: Warning  # Override default severity
  debounceSeconds: 300
```

The generic adapter extracts:
- Name from `metadata.name`
- Namespace from `metadata.namespace`
- Labels from `metadata.labels`
- Summary from `spec.description` (if present)

### Field-Path Configuration

When a CRD stores its selectors, effects, or summaries in non-standard locations, use `fieldPaths` to tell the generic adapter where to find them:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-deployment-restrictions
spec:
  gvr:
    group: policy.company.com
    version: v1
    resource: deploymentrestrictions
  adapter: generic
  enabled: true
  severity: Warning
  fieldPaths:
    selectorPath: "spec.target.workloads"
    namespaceSelectorPath: "spec.scope.namespaces"
    effectPath: "spec.action"
    summaryPath: "spec.description"
```

Field paths use dot notation (e.g., `spec.target.workloads`). All field-path settings are optional — when unset, the generic adapter uses its default extraction logic.

**Precedence:** Resource annotations (`potoo.io/severity`, `potoo.io/summary`) always take precedence over profile-configured values.

---

## Adapter Health

Check adapter status via the API:

```bash
curl http://potoo-controller:8092/api/v1/capabilities
```

Response:
```json
{
  "adapters": [
    "networkpolicy",
    "resourcequota",
    "webhook",
    "cilium",
    "gatekeeper"
  ],
  "constraintTypes": {
    "NetworkIngress": 5,
    "NetworkEgress": 12,
    "Admission": 8,
    "ResourceLimit": 3
  }
}
```

Or via MCP:
```json
{
  "tool": "potoo_list_namespaces"
}
```

---

## Adapter Error Handling

When an adapter fails to parse a resource:

1. **Log Error**: Detailed error in controller logs
2. **Metric Increment**: `potoo_adapter_parse_errors` counter
3. **Continue Processing**: Other resources still processed
4. **No Constraint Created**: Unparseable resources are skipped

Errors are typically caused by:
- Unexpected CRD schema changes
- Nil field access (fixed by safe field helpers)
- Version mismatches

---

## Writing Custom Adapters

For in-tree adapters, follow this pattern:

{% raw %}
```go
// internal/adapters/myengine/adapter.go
package myengine

import (
    "context"
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "k8s.io/apimachinery/pkg/runtime/schema"
    "github.com/potooio/docs/internal/types"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string { return "myengine" }

func (a *Adapter) Handles() []schema.GroupVersionResource {
    return []schema.GroupVersionResource{
        {Group: "myengine.io", Version: "v1", Resource: "policies"},
    }
}

func (a *Adapter) Parse(
    ctx context.Context,
    obj *unstructured.Unstructured,
) ([]types.Constraint, error) {
    // Use internal/util for safe field access
    name := util.GetString(obj.Object, "metadata", "name")

    return []types.Constraint{{
        UID:            obj.GetUID(),
        Name:           name,
        Namespace:      obj.GetNamespace(),
        ConstraintType: types.ConstraintTypeAdmission,
        Severity:       types.SeverityWarning,
        Effect:         "warn",
        Summary:        "Custom policy applies",
    }}, nil
}
```
{% endraw %}

Register in `internal/adapters/registry.go`.

---

## Troubleshooting

### Adapter Not Detecting CRDs

```bash
# Check CRD exists
kubectl get crd ciliumnetworkpolicies.cilium.io

# Check controller logs
kubectl logs -n potoo-system -l app=potoo-controller | grep cilium

# Check adapter status
curl http://potoo-controller:8092/api/v1/capabilities
```

### Parse Errors

```bash
# Check for parse errors
kubectl logs -n potoo-system -l app=potoo-controller | grep "parse error"

# Check metrics
curl http://potoo-controller:8080/metrics | grep adapter_parse_errors
```

### RBAC Issues

```bash
# Verify ClusterRole has access
kubectl auth can-i get ciliumnetworkpolicies --as=system:serviceaccount:potoo-system:potoo-controller
```
