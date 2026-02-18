---
layout: default
title: Resources
parent: MCP Server
nav_order: 2
---

# MCP Resources Reference
{: .no_toc }

Resources are read-only data endpoints that agents can access.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## reports

Get the full constraint report for a namespace.

### Path

```
/resources/reports/{namespace}
```

### Request

```json
{
  "resource": "reports",
  "params": {
    "namespace": "production"
  }
}
```

Or via HTTP:
```bash
curl http://potoo-controller:8090/resources/reports/production
```

### Response

```json
{
  "namespace": "production",
  "constraintCount": 5,
  "criticalCount": 2,
  "warningCount": 2,
  "infoCount": 1,
  "schemaVersion": "1",
  "detailLevel": "summary",
  "generatedAt": "2024-01-15T10:30:00Z",
  "constraints": [
    {
      "name": "restrict-egress",
      "type": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "source": "NetworkPolicy",
      "tags": ["network", "egress"],
      "remediation": {
        "summary": "Request network policy exception",
        "steps": [
          {
            "type": "manual",
            "description": "Contact platform team"
          }
        ]
      }
    },
    {
      "name": "require-limits",
      "type": "Admission",
      "severity": "Critical",
      "effect": "deny",
      "source": "ValidatingWebhookConfiguration",
      "tags": ["admission", "resources"]
    },
    {
      "name": "compute-quota",
      "type": "ResourceLimit",
      "severity": "Warning",
      "effect": "limit",
      "source": "ResourceQuota",
      "tags": ["quota", "cpu", "memory"]
    }
  ]
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `namespace` | string | The queried namespace |
| `constraintCount` | int | Total constraints |
| `criticalCount` | int | Critical severity count |
| `warningCount` | int | Warning severity count |
| `infoCount` | int | Info severity count |
| `schemaVersion` | string | Schema version for compatibility |
| `detailLevel` | string | Privacy level applied |
| `generatedAt` | string | ISO 8601 timestamp |
| `constraints` | array | Constraint entries |

---

## constraints

Get a single constraint by name.

### Path

```
/resources/constraints/{namespace}/{name}
```

### Request

```json
{
  "resource": "constraints",
  "params": {
    "namespace": "production",
    "name": "restrict-egress"
  }
}
```

Or via HTTP:
```bash
curl http://potoo-controller:8090/resources/constraints/production/restrict-egress
```

### Response

```json
{
  "name": "restrict-egress",
  "namespace": "production",
  "constraint_type": "NetworkEgress",
  "severity": "Critical",
  "source_kind": "NetworkPolicy",
  "source_api_version": "networking.k8s.io/v1",
  "effect": "deny",
  "affected_workloads": ["api-server", "worker", "scheduler"],
  "tags": ["network", "egress", "port-restriction"],
  "detail_level": "summary",
  "last_observed": "2024-01-15T10:30:00Z",
  "remediation": {
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
      }
    ]
  },
  "metrics": null
}
```

### Metrics (ResourceLimit only)

For ResourceLimit constraints, the `metrics` field contains usage data:

```json
{
  "name": "compute-quota",
  "constraint_type": "ResourceLimit",
  "metrics": {
    "cpu": {
      "hard": "4",
      "used": "3.12",
      "unit": "cores",
      "percent_used": 78.0
    },
    "memory": {
      "hard": "8Gi",
      "used": "6Gi",
      "unit": "bytes",
      "percent_used": 75.0
    }
  }
}
```

### Error Response

```json
{
  "error": "Constraint not found"
}
```

---

## health

Get controller health status.

### Path

```
/resources/health
```

### Request

```json
{
  "resource": "health"
}
```

Or via HTTP:
```bash
curl http://potoo-controller:8090/resources/health
```

### Response

```json
{
  "status": "healthy",
  "adapters": {
    "networkpolicy": {
      "enabled": true,
      "watched_resources": 1,
      "error_count": 0
    },
    "resourcequota": {
      "enabled": true,
      "watched_resources": 2,
      "error_count": 0
    },
    "cilium": {
      "enabled": true,
      "watched_resources": 2,
      "error_count": 0
    },
    "gatekeeper": {
      "enabled": false,
      "watched_resources": 0,
      "error_count": 0,
      "reason": "CRDs not installed"
    }
  },
  "hubble": {
    "enabled": true,
    "connected": true,
    "address": "hubble-relay.kube-system.svc:4245"
  },
  "mcp": {
    "enabled": true,
    "transport": "sse",
    "port": 8090
  },
  "indexer": {
    "total_constraints": 47,
    "namespaces_with_constraints": 12
  },
  "last_scan": "2024-01-15T10:30:00Z"
}
```

### Status Values

| Status | Meaning |
|--------|---------|
| `healthy` | All components operational |
| `degraded` | Some adapters failing |
| `unhealthy` | Core functionality impaired |

### Adapter Health Fields

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | boolean | Whether adapter is active |
| `watched_resources` | int | Number of resource types watched |
| `error_count` | int | Parse errors since startup |
| `reason` | string | Why disabled (if disabled) |

---

## capabilities

Get controller capabilities and feature status.

### Path

```
/resources/capabilities
```

### Request

```json
{
  "resource": "capabilities"
}
```

Or via HTTP:
```bash
curl http://potoo-controller:8090/resources/capabilities
```

### Response

```json
{
  "version": "1",
  "adapters": [
    "networkpolicy",
    "resourcequota",
    "limitrange",
    "webhookconfig",
    "cilium"
  ],
  "constraintTypes": {
    "NetworkIngress": 8,
    "NetworkEgress": 15,
    "Admission": 12,
    "ResourceLimit": 6,
    "MeshPolicy": 4,
    "MissingResource": 2
  },
  "totalConstraints": 47,
  "namespaceCount": 12,
  "hubbleEnabled": true,
  "mcpEnabled": true,
  "lastScan": "2024-01-15T10:30:00Z"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | API version |
| `adapters` | array | Enabled adapter names |
| `constraintTypes` | object | Count by constraint type |
| `totalConstraints` | int | Total constraints in index |
| `namespaceCount` | int | Namespaces with constraints |
| `hubbleEnabled` | boolean | Hubble integration active |
| `mcpEnabled` | boolean | MCP server active |
| `lastScan` | string | Last CRD scan timestamp |

---

## HTTP Access

All resources are also available via HTTP GET:

```bash
# Health
curl http://potoo-controller:8090/resources/health

# Capabilities
curl http://potoo-controller:8090/resources/capabilities

# Report for namespace
curl http://potoo-controller:8090/resources/reports/production

# Single constraint
curl http://potoo-controller:8090/resources/constraints/production/restrict-egress
```

### Port Forwarding for Local Access

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090

# Then access locally
curl http://localhost:8090/resources/health
```

---

## Privacy Scoping

Resources respect the same privacy model as tools:

| Detail Level | What's Visible |
|--------------|----------------|
| `summary` | Basic info, same-namespace names only |
| `detailed` | + port numbers, effect details |
| `full` | + cross-namespace policy names |

The `detailLevel` field in responses indicates what level was applied.
