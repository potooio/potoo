---
layout: default
title: Tools
parent: MCP Server
nav_order: 1
---

# MCP Tools Reference
{: .no_toc }

Tools are functions that AI agents can invoke.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## potoo_query

Query constraints affecting a namespace.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | Yes | Namespace to query |
| `workload_name` | string | No | Filter by workload name |
| `workload_labels` | object | No | Filter by label selector |
| `constraint_type` | string | No | Filter by type |
| `severity` | string | No | Filter by severity |
| `include_remediation` | boolean | No | Include remediation steps |

### Request

```json
{
  "tool": "potoo_query",
  "params": {
    "namespace": "production",
    "constraint_type": "NetworkEgress",
    "severity": "Critical",
    "include_remediation": true
  }
}
```

### Response

```json
{
  "namespace": "production",
  "constraints": [
    {
      "name": "restrict-egress",
      "namespace": "production",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "source_kind": "NetworkPolicy",
      "source_api_version": "networking.k8s.io/v1",
      "effect": "deny",
      "affected_workloads": ["api-server", "worker"],
      "tags": ["network", "egress", "port-restriction"],
      "detail_level": "summary",
      "last_observed": "2024-01-15T10:30:00Z",
      "remediation": {
        "summary": "Request network policy exception",
        "steps": [
          {
            "type": "manual",
            "description": "Contact platform team",
            "contact": "platform-team@company.com",
            "requires_privilege": "developer",
            "automated": false
          }
        ]
      }
    }
  ],
  "total": 1
}
```

{: .note }
> For `ResourceLimit` constraints, the response includes a `metrics` field with resource usage data. See the [metrics example in the Resources reference](/docs/mcp/resources/#metrics-resourcelimit-only) for the full schema.

### Constraint Types

Valid values for `constraint_type`:
- `NetworkIngress`
- `NetworkEgress`
- `Admission`
- `ResourceLimit`
- `MeshPolicy`
- `MissingResource`
- `Unknown`

### Severity Levels

Valid values for `severity`:
- `Critical`
- `Warning`
- `Info`

---

## potoo_explain

Analyze an error message and identify matching constraints.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `error_message` | string | Yes | The error message to analyze |
| `namespace` | string | Yes | Namespace context |
| `workload_name` | string | No | Workload for additional context |

### Request

```json
{
  "tool": "potoo_explain",
  "params": {
    "error_message": "connection timed out to port 9090",
    "namespace": "my-app",
    "workload_name": "api-server"
  }
}
```

### Response

```json
{
  "explanation": "This error appears to be network-related. The following network policies may be blocking traffic.",
  "matching_constraints": [
    {
      "name": "restrict-egress",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "NetworkPolicy",
      "remediation": {
        "summary": "Request network policy exception",
        "steps": [...]
      }
    }
  ],
  "confidence": "high",
  "remediation_steps": [
    {
      "type": "manual",
      "description": "Contact platform team",
      "contact": "platform-team@company.com",
      "requires_privilege": "developer",
      "automated": false
    }
  ]
}
```

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `high` | Strong keyword match to constraint type |
| `medium` | Partial match, multiple possible causes |
| `low` | No clear match, all constraints returned |

### Pattern Matching

The tool matches these error patterns:

**Network errors** → NetworkIngress/NetworkEgress:
- connection refused/timed out
- network unreachable
- no route to host
- dial tcp, i/o timeout

**Admission errors** → Admission:
- denied, rejected, forbidden
- admission, webhook
- not allowed, policy violation

**Quota errors** → ResourceLimit:
- exceeded quota
- limit exceeded, insufficient
- cpu, memory, storage

---

## potoo_check

Pre-check whether a manifest would be blocked by constraints.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `manifest` | string | Yes | YAML manifest to check |

### Request

```json
{
  "tool": "potoo_check",
  "params": {
    "manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\n  namespace: production\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: my-app\n  template:\n    metadata:\n      labels:\n        app: my-app\n    spec:\n      containers:\n        - name: app\n          image: nginx"
  }
}
```

### Response

```json
{
  "would_block": true,
  "blocking_constraints": [
    {
      "name": "require-limits",
      "constraint_type": "Admission",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "ValidatingWebhookConfiguration",
      "remediation": {
        "summary": "Add resource limits",
        "steps": [
          {
            "type": "yaml_patch",
            "description": "Add resources section",
            "template": "resources:\n  limits:\n    cpu: 500m\n    memory: 256Mi",
            "requires_privilege": "developer",
            "automated": true
          }
        ]
      }
    }
  ],
  "missing_prerequisites": [
    {
      "expected_kind": "ServiceMonitor",
      "expected_api_version": "monitoring.coreos.com/v1",
      "reason": "Workload has a port named metrics or http-metrics but no Prometheus monitor targets it",
      "severity": "Warning",
      "for_workload": "production/Deployment/my-app"
    }
  ],
  "warnings": [
    "restrict-egress: Egress limited to ports 443, 8443"
  ]
}
```

### Missing Prerequisites

The `missing_prerequisites` array identifies companion resources that the workload needs but that don't exist in the cluster. For example, if a Deployment has a `prometheus.io/scrape: "true"` annotation but no corresponding `ServiceMonitor` exists, Potoo detects this and includes it in the response.

Built-in detection rules:

| Rule | Trigger | Expected Resource |
|------|---------|-------------------|
| PrometheusMonitor | `prometheus.io/scrape` annotation or metrics port | `ServiceMonitor` |
| IstioRouting | Istio sidecar injection | `VirtualService` |
| IstioMTLS | Mesh membership | `PeerAuthentication` |
| CertIssuer | TLS Secret references | `Certificate` / `Issuer` |

Each entry includes:

| Field | Type | Description |
|-------|------|-------------|
| `expected_kind` | string | Kind that should exist (e.g., `ServiceMonitor`) |
| `expected_api_version` | string | API version (e.g., `monitoring.coreos.com/v1`) |
| `reason` | string | Why this resource is expected |
| `severity` | string | `Warning` or `Info` |
| `for_workload` | string | Which workload needs it (e.g., `production/Deployment/my-app`) |
| `remediation` | object | Steps to create the missing resource (when available) |

### Blocking Logic

A manifest is marked as `would_block: true` when:
- Any Admission constraint with Critical severity applies
- The manifest matches the constraint's selector

Non-blocking issues are returned as `warnings`. Missing prerequisites are informational and do not affect `would_block`.

---

## potoo_list_namespaces

List all namespaces with constraint summaries.

### Parameters

None.

### Request

```json
{
  "tool": "potoo_list_namespaces"
}
```

### Response

```json
[
  {
    "namespace": "production",
    "total": 5,
    "critical_count": 2,
    "warning_count": 2,
    "info_count": 1,
    "top_constraint": "restrict-egress"
  },
  {
    "namespace": "staging",
    "total": 3,
    "critical_count": 1,
    "warning_count": 1,
    "info_count": 1,
    "top_constraint": "require-limits"
  }
]
```

### Use Cases

- Get cluster overview
- Find namespaces with critical constraints
- Navigate to specific namespace for detailed query

---

## potoo_remediation

Get detailed remediation steps for a specific constraint.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `constraint_name` | string | Yes | Name of the constraint |
| `namespace` | string | Yes | Namespace context |

### Request

```json
{
  "tool": "potoo_remediation",
  "params": {
    "constraint_name": "restrict-egress",
    "namespace": "production"
  }
}
```

### Response

```json
{
  "summary": "Request network policy exception to allow egress",
  "steps": [
    {
      "type": "manual",
      "description": "Contact platform team to request egress exception",
      "contact": "platform-team@company.com",
      "requires_privilege": "developer",
      "automated": false
    },
    {
      "type": "kubectl",
      "description": "Add exception annotation to workload",
      "command": "kubectl annotate deployment my-app potoo.io/egress-exception=requested",
      "requires_privilege": "namespace-admin",
      "automated": true
    },
    {
      "type": "link",
      "description": "Review network policy documentation",
      "url": "https://wiki.company.com/network-policies",
      "automated": false
    }
  ]
}
```

### Remediation Step Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `manual` | Human action required | description, contact |
| `kubectl` | kubectl command | description, command |
| `annotation` | Add annotation | description, patch |
| `yaml_patch` | Modify manifest | description, template |
| `link` | Documentation link | description, url |

### Automation

Steps with `automated: true` can be executed programmatically. These include:
- `kubectl` commands
- `annotation` patches

---

## Error Responses

All tools return errors in this format:

```json
{
  "error": "namespace is required"
}
```

### Common Errors

| Error | Cause |
|-------|-------|
| `namespace is required` | Missing required parameter |
| `Constraint not found` | Constraint name doesn't exist |
| `Invalid YAML manifest` | Malformed YAML in check |
| `Invalid request body` | Malformed JSON request |

---

## Rate Limiting

MCP tools respect the same rate limits as other notification channels:
- Default: 100 requests/minute per namespace
- Configurable via `notifications.rateLimitPerMinute`
