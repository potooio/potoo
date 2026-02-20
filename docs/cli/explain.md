---
layout: default
title: explain
parent: CLI (potoo)
nav_order: 2
---

# potoo explain
{: .no_toc }

Explain which constraint caused an error.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Synopsis

```bash
potoo explain -n <namespace> "<error-message>" [flags]
```

---

## Description

The `explain` command analyzes an error message and identifies constraints that may have caused it. This is the primary troubleshooting tool for developers encountering cryptic errors.

The command uses pattern matching to correlate error messages with constraint types:

| Error Pattern | Matched Constraint Type |
|---------------|------------------------|
| connection refused, timed out, no route | NetworkIngress, NetworkEgress |
| denied, rejected, forbidden, webhook | Admission |
| exceeded quota, insufficient, limit | ResourceLimit |

---

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--namespace` | `-n` | Yes | Namespace context for the error |
| `--workload` | | No | Workload name for additional context |
| `--output` | `-o` | No | Output format: table, json, yaml |

---

## Confidence Levels

The command reports confidence in its match:

| Level | Meaning |
|-------|---------|
| `high` | Strong keyword match (e.g., "connection refused" + NetworkPolicy exists) |
| `medium` | Partial match or multiple possible causes |
| `low` | No clear match; all constraints shown as possibilities |

---

## Examples

### Network Error

```bash
potoo explain -n my-namespace "connection timed out to port 9090"
```

Output:
```
Error:       connection timed out to port 9090
Confidence:  high
Explanation: This error appears to be network-related. The following
             network policies may be blocking traffic.

Matching Constraints:
  NAME             TYPE           SEVERITY   EFFECT
  restrict-egress  NetworkEgress  Critical   deny

Remediation Steps:
  1. [manual] Contact platform-team@company.com to request an egress exception
  2. [kubectl] kubectl annotate pod <pod-name> potoo.io/egress-exception=true
```

### Admission Error

```bash
potoo explain -n my-namespace "admission webhook denied the request: pods must have resource limits"
```

Output:
```
Error:       admission webhook denied the request: pods must have resource limits
Confidence:  high
Explanation: This error appears to be from an admission controller. The following
             admission policies may be rejecting the request.

Matching Constraints:
  NAME            TYPE       SEVERITY   EFFECT
  require-limits  Admission  Critical   deny

Remediation Steps:
  1. [yaml_patch] Add resource limits to your pod spec:
     resources:
       limits:
         cpu: "500m"
         memory: "256Mi"
       requests:
         cpu: "100m"
         memory: "128Mi"
```

### Quota Error

```bash
potoo explain -n my-namespace "exceeded quota: requested cpu 2, limit 1"
```

Output:
```
Error:       exceeded quota: requested cpu 2, limit 1
Confidence:  high
Explanation: This error appears to be quota-related. The following
             resource quotas may be limiting resources.

Matching Constraints:
  NAME           TYPE           SEVERITY   EFFECT
  compute-quota  ResourceLimit  Warning    limit

Remediation Steps:
  1. [manual] Request quota increase from platform team
  2. [link] See quota request process: https://wiki.company.com/quota-requests
```

### Unknown Error (Low Confidence)

```bash
potoo explain -n my-namespace "unknown error occurred"
```

Output:
```
Error:       unknown error occurred
Confidence:  low
Explanation: Could not determine the specific cause. Here are all constraints
             in the namespace that might be relevant.

Matching Constraints:
  NAME             TYPE           SEVERITY   EFFECT
  restrict-egress  NetworkEgress  Critical   deny
  require-limits   Admission      Critical   deny
  compute-quota    ResourceLimit  Warning    limit
```

### JSON Output

```bash
potoo explain -n my-namespace "connection refused" -o json
```

Output:
```json
{
  "error_message": "connection refused",
  "explanation": "This error appears to be network-related. The following network policies may be blocking traffic.",
  "confidence": "high",
  "matching_constraints": [
    {
      "name": "restrict-egress",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "NetworkPolicy",
      "remediation": {
        "summary": "Request network policy exception",
        "steps": [
          {
            "type": "manual",
            "description": "Contact platform team",
            "contact": "platform-team@company.com"
          }
        ]
      }
    }
  ],
  "remediation_steps": [
    {
      "type": "manual",
      "description": "Contact platform team",
      "contact": "platform-team@company.com",
      "requires_privilege": "developer"
    }
  ]
}
```

---

## Error Pattern Matching

The explain command matches these patterns:

### Network Patterns
- `connection refused`
- `connection timed out`
- `network unreachable`
- `no route to host`
- `dial tcp`
- `i/o timeout`
- `egress`
- `ingress`

### Admission Patterns
- `denied`
- `rejected`
- `forbidden`
- `admission`
- `webhook`
- `not allowed`
- `policy violation`
- `constraint`

### Quota Patterns
- `exceeded quota`
- `resource quota`
- `limit exceeded`
- `insufficient`
- `cpu`
- `memory`
- `storage`

---

## Response Schema

### ExplainResult

| Field | Type | Description |
|-------|------|-------------|
| `error_message` | string | The input error message |
| `explanation` | string | Human-readable explanation |
| `confidence` | string | high, medium, or low |
| `matching_constraints` | ConstraintInfo[] | Constraints that may have caused the error |
| `remediation_steps` | RemediationStep[] | Aggregated remediation steps |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (even if no matches found) |
| 1 | Error (invalid flags, API error, etc.) |

---

## See Also

- [query](query.html) - List all constraints in a namespace
- [remediate](remediate.html) - Get detailed remediation for a specific constraint
