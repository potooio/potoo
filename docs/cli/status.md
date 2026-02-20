---
layout: default
title: status
parent: CLI (potoo)
nav_order: 5
---

# potoo status
{: .no_toc }

Show cluster-wide constraint summary.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Synopsis

```bash
potoo status [flags]
```

---

## Description

The `status` command provides a cluster-wide overview of constraints across all namespaces. It aggregates data from all ConstraintReport CRDs.

This command is useful for:
- Platform teams monitoring constraint health
- Dashboards and monitoring integrations
- Quick cluster-wide assessment

---

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--output` | `-o` | No | Output format: table, json, yaml |

---

## Examples

### Basic Status

```bash
potoo status
```

Output:
```
NAMESPACE         TOTAL   CRITICAL   WARNING   INFO
production        5       2          2         1
staging           3       1          1         1
development       8       0          4         4
kube-system       1       0          1         0
---
Total: 17 constraints across 4 namespaces
Critical: 3, Warning: 8, Info: 6
```

### JSON Output

```bash
potoo status -o json
```

Output:
```json
{
  "namespace_summaries": [
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
    },
    {
      "namespace": "development",
      "total": 8,
      "critical_count": 0,
      "warning_count": 4,
      "info_count": 4,
      "top_constraint": "compute-quota"
    },
    {
      "namespace": "kube-system",
      "total": 1,
      "critical_count": 0,
      "warning_count": 1,
      "info_count": 0,
      "top_constraint": "default-deny-egress"
    }
  ],
  "total_constraints": 17,
  "total_critical": 3,
  "total_warning": 8,
  "total_info": 6,
  "namespace_count": 4
}
```

### YAML Output

```bash
potoo status -o yaml
```

Output:
```yaml
namespace_summaries:
  - namespace: production
    total: 5
    critical_count: 2
    warning_count: 2
    info_count: 1
    top_constraint: restrict-egress
  - namespace: staging
    total: 3
    critical_count: 1
    warning_count: 1
    info_count: 1
    top_constraint: require-limits
total_constraints: 17
total_critical: 3
total_warning: 8
total_info: 6
namespace_count: 4
```

---

## Response Schema

### StatusResult

| Field | Type | Description |
|-------|------|-------------|
| `namespace_summaries` | NamespaceSummary[] | Per-namespace breakdown |
| `total_constraints` | int | Total constraints cluster-wide |
| `total_critical` | int | Total Critical severity |
| `total_warning` | int | Total Warning severity |
| `total_info` | int | Total Info severity |
| `namespace_count` | int | Number of namespaces with constraints |

### NamespaceSummary

| Field | Type | Description |
|-------|------|-------------|
| `namespace` | string | Namespace name |
| `total` | int | Total constraints in namespace |
| `critical_count` | int | Critical severity count |
| `warning_count` | int | Warning severity count |
| `info_count` | int | Info severity count |
| `top_constraint` | string | Highest-severity constraint name |

---

## Use Cases

### Monitoring Dashboard

```bash
# Get critical count for alerting
critical=$(potoo status -o json | jq '.total_critical')
if [ "$critical" -gt 0 ]; then
  echo "ALERT: $critical critical constraints in cluster"
fi
```

### Prometheus Metrics Export

```bash
#!/bin/bash
# Export as Prometheus metrics

potoo status -o json | jq -r '
  "potoo_constraints_total " + (.total_constraints | tostring),
  "potoo_constraints_critical " + (.total_critical | tostring),
  "potoo_constraints_warning " + (.total_warning | tostring),
  "potoo_constraints_info " + (.total_info | tostring)
'
```

Output:
```
potoo_constraints_total 17
potoo_constraints_critical 3
potoo_constraints_warning 8
potoo_constraints_info 6
```

### Find High-Risk Namespaces

```bash
# List namespaces with critical constraints
potoo status -o json | \
  jq -r '.namespace_summaries[] | select(.critical_count > 0) | "\(.namespace): \(.critical_count) critical"'
```

Output:
```
production: 2 critical
staging: 1 critical
```

---

## RBAC Requirements

The status command requires read access to ConstraintReports across all namespaces:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: potoo-status-reader
rules:
  - apiGroups: ["potoo.io"]
    resources: ["constraintreports"]
    verbs: ["get", "list"]
```

If you only have namespace-scoped access, the command will only show namespaces you can access.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (API error, RBAC issues, etc.) |

---

## See Also

- [query](query.html) - Drill into a specific namespace
- [Controller Status](/docs/controller/) - Controller health and metrics
