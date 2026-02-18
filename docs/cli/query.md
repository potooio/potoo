---
layout: default
title: query
parent: CLI (potoo)
nav_order: 1
---

# potoo query
{: .no_toc }

Query constraints affecting a namespace.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Synopsis

```bash
potoo query -n <namespace> [flags]
```

---

## Description

The `query` command retrieves all constraints affecting workloads in a namespace. It reads from the ConstraintReport CRD created by the Potoo controller.

Results are sorted by severity (Critical first, then Warning, then Info).

---

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--namespace` | `-n` | Yes | Namespace to query |
| `--type` | | No | Filter by constraint type |
| `--severity` | | No | Filter by severity level |
| `--workload` | | No | Filter by workload name |
| `--output` | `-o` | No | Output format: table, json, yaml |

### Constraint Types

Valid values for `--type`:
- `NetworkIngress` - Inbound network restrictions
- `NetworkEgress` - Outbound network restrictions
- `Admission` - Admission webhook/policy rejections
- `ResourceLimit` - Quota and limit range restrictions
- `MeshPolicy` - Service mesh authorization policies
- `MissingResource` - Required companion resources not found

### Severity Levels

Valid values for `--severity`:
- `Critical` - Active blocking (traffic drops, admission rejections)
- `Warning` - Approaching limits, audit violations
- `Info` - Informational, not actively blocking

---

## Examples

### Query All Constraints

```bash
potoo query -n my-namespace
```

Output:
```
NAMESPACE     NAME               TYPE            SEVERITY   EFFECT
my-namespace  restrict-egress    NetworkEgress   Critical   deny
my-namespace  require-limits     Admission       Critical   deny
my-namespace  compute-quota      ResourceLimit   Warning    limit
my-namespace  allow-internal     NetworkIngress  Info       restrict
```

### Filter by Type

```bash
potoo query -n my-namespace --type NetworkEgress
```

Output:
```
NAMESPACE     NAME             TYPE           SEVERITY   EFFECT
my-namespace  restrict-egress  NetworkEgress  Critical   deny
```

### Filter by Severity

```bash
potoo query -n my-namespace --severity Critical
```

Output:
```
NAMESPACE     NAME             TYPE           SEVERITY   EFFECT
my-namespace  restrict-egress  NetworkEgress  Critical   deny
my-namespace  require-limits   Admission      Critical   deny
```

### JSON Output

```bash
potoo query -n my-namespace -o json
```

Output:
```json
{
  "namespace": "my-namespace",
  "constraints": [
    {
      "name": "restrict-egress",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "NetworkPolicy",
      "source_api_version": "networking.k8s.io/v1",
      "affected_workloads": ["api-server", "worker"],
      "tags": ["network", "egress", "port-restriction"],
      "detail_level": "summary",
      "last_observed": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### JSON with Remediation

The JSON output includes remediation information when available:

```json
{
  "constraints": [
    {
      "name": "restrict-egress",
      "remediation": {
        "summary": "Request network policy exception",
        "steps": [
          {
            "type": "manual",
            "description": "Contact platform team to request egress exception",
            "contact": "platform-team@company.com",
            "requires_privilege": "developer"
          },
          {
            "type": "kubectl",
            "description": "Add exception annotation to workload",
            "command": "kubectl annotate deployment my-app potoo.io/egress-exception=true",
            "requires_privilege": "namespace-admin"
          }
        ]
      }
    }
  ]
}
```

---

## Response Schema

### QueryResult

| Field | Type | Description |
|-------|------|-------------|
| `namespace` | string | Queried namespace |
| `constraints` | ConstraintInfo[] | List of matching constraints |
| `total` | int | Total count |

### ConstraintInfo

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Constraint name (may be redacted per privacy) |
| `constraint_type` | string | Type classification |
| `severity` | string | Critical, Warning, or Info |
| `effect` | string | deny, restrict, warn, audit, limit |
| `source_kind` | string | Kubernetes kind (NetworkPolicy, etc.) |
| `source_api_version` | string | API version of source |
| `affected_workloads` | string[] | Workload names affected |
| `message` | string | Human-readable summary |
| `tags` | string[] | Filtering tags |
| `remediation` | RemediationInfo | Remediation steps (if available) |
| `detail_level` | string | Privacy level applied |
| `last_observed` | string | ISO 8601 timestamp |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid flags, API error, etc.) |

---

## See Also

- [explain](../explain/) - Match errors to constraints
- [check](../check/) - Pre-check manifests
- [remediate](../remediate/) - Get remediation for a specific constraint
