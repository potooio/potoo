---
layout: default
title: Reference
nav_order: 7
has_children: true
permalink: /docs/reference/
---

# Reference
{: .no_toc }

Technical reference documentation for Potoo.
{: .fs-6 .fw-300 }

---

## Contents

| Topic | Description |
|-------|-------------|
| [Constraint Types](constraint-types.html) | NetworkIngress, NetworkEgress, Admission, ResourceLimit, MeshPolicy, MissingResource |
| [Severity Levels](severity-levels.html) | Critical, Warning, Info definitions and thresholds |

---

## Quick Reference

### Constraint Types

| Type | Description | Common Sources |
|------|-------------|----------------|
| `NetworkIngress` | Inbound traffic restrictions | NetworkPolicy, CiliumNetworkPolicy |
| `NetworkEgress` | Outbound traffic restrictions | NetworkPolicy, CiliumNetworkPolicy |
| `Admission` | Resource rejection | Webhooks, Gatekeeper, Kyverno |
| `ResourceLimit` | Quota/limit enforcement | ResourceQuota, LimitRange |
| `MeshPolicy` | Service mesh authorization | Istio AuthorizationPolicy |
| `MissingResource` | Expected resource not found | ServiceMonitor, VirtualService |
| `Unknown` | Unclassified policy | Generic adapter |

### Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| `Critical` | Active blocking | Traffic dropped, pods rejected |
| `Warning` | Potential issue | Quota at 75%, audit violations |
| `Info` | Informational | Best-practice suggestions |

---

## Effects

Constraints have an effect that describes what they do:

| Effect | Meaning |
|--------|---------|
| `deny` | Blocks/rejects by default |
| `restrict` | Allows only specific cases |
| `warn` | Logs but allows |
| `audit` | Records for compliance |
| `limit` | Caps at threshold |
| `require` | Mandates something (mTLS) |
| `missing` | Expected resource absent |

---

## Tags

Constraints have tags for filtering:

| Category | Example Tags |
|----------|--------------|
| Network | `network`, `ingress`, `egress`, `port-restriction` |
| Admission | `admission`, `gatekeeper`, `kyverno`, `labels` |
| Resources | `quota`, `cpu`, `memory`, `storage` |
| Mesh | `mesh`, `istio`, `mtls`, `authorization` |
| Missing | `missing`, `prometheus`, `monitoring` |

Filter by tag with MCP:
```json
{
  "tool": "potoo_query",
  "params": {
    "namespace": "my-namespace"
  }
}
// Response includes tags for client-side filtering
```

---

## Detail Levels

Privacy-scoped detail levels:

| Level | Developers See | Admins See |
|-------|----------------|------------|
| `summary` | Type, existence, guidance | Everything |
| `detailed` | + ports, effects | Everything |
| `full` | Everything | Everything |

---

## API Versions

| Resource | Current Version |
|----------|-----------------|
| ConstraintReport | `potoo.io/v1alpha1` |
| ConstraintProfile | `potoo.io/v1alpha1` |
| NotificationPolicy | `potoo.io/v1alpha1` |
| MCP Schema | `1` |

---

## Ports

| Port | Service | Protocol |
|------|---------|----------|
| 8080 | Metrics + Health | HTTP |
| 8090 | MCP Server | HTTP (SSE) |
| 8092 | API Server | HTTP |
| 9443 | Admission Webhook | HTTPS |

---

## Metrics

Key Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `potoo_constraints_total` | Gauge | Total constraints |
| `potoo_constraints_by_type` | Gauge | By constraint type |
| `potoo_constraints_by_severity` | Gauge | By severity |
| `potoo_adapter_parse_errors` | Counter | Parse failures |
| `potoo_notifications_sent` | Counter | By channel |
