---
layout: default
title: Severity Levels
parent: Reference
nav_order: 2
---

# Severity Levels
{: .no_toc }

Reference for constraint severity classifications.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Every constraint has a severity level indicating how urgently it needs attention:

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| **Critical** | Active blocking | Immediate |
| **Warning** | Potential issues | Soon |
| **Info** | Informational | None |

---

## Critical

### Definition
The constraint is actively blocking traffic, rejecting resources, or preventing deployments.

### Examples
- NetworkPolicy dropping traffic
- Admission webhook rejecting pods
- Resource quota exceeded (scheduling blocked)

### Typical Sources
- NetworkPolicy with deny-all + explicit allow
- ValidatingWebhookConfiguration in enforce mode
- ResourceQuota at 100% usage
- Gatekeeper Constraints in enforce mode

### Response
Immediate action required. Workloads are impacted.

### CLI Output
```bash
$ potoo query -n my-namespace --severity Critical

NAMESPACE     NAME             TYPE           SEVERITY   EFFECT
my-namespace  restrict-egress  NetworkEgress  Critical   deny
my-namespace  require-limits   Admission      Critical   deny
```

---

## Warning

### Definition
The constraint may cause issues soon or is logging violations but not blocking.

### Examples
- Resource quota at 75%+ usage
- Gatekeeper Constraint in audit mode
- Missing ServiceMonitor (monitoring gap)
- Approaching rate limits

### Typical Sources
- ResourceQuota with high utilization
- Gatekeeper/Kyverno in audit mode
- LimitRange with default values
- MissingResource detections

### Response
Address when convenient. May become Critical if ignored.

### CLI Output
```bash
$ potoo query -n my-namespace --severity Warning

NAMESPACE     NAME            TYPE            SEVERITY   EFFECT
my-namespace  compute-quota   ResourceLimit   Warning    limit
my-namespace  audit-labels    Admission       Warning    audit
```

---

## Info

### Definition
Informational constraint that is not actively blocking and unlikely to cause issues.

### Examples
- NetworkPolicy that only affects specific workloads
- Admission policy in warn mode
- Best-practice recommendations

### Typical Sources
- NetworkPolicy with narrow scope
- Kyverno in audit mode with warn
- Optional configuration suggestions

### Response
No action required. Good to be aware of.

### CLI Output
```bash
$ potoo query -n my-namespace --severity Info

NAMESPACE     NAME            TYPE           SEVERITY   EFFECT
my-namespace  recommended     Admission      Info       warn
```

---

## How Severity is Determined

Adapters assign severity based on:

### Network Policies

| Condition | Severity |
|-----------|----------|
| Default deny + no matching allow | Critical |
| Restricts specific ports | Critical |
| Allows most traffic with restrictions | Warning |

### Admission Policies

| Condition | Severity |
|-----------|----------|
| Enforce mode | Critical |
| Audit mode | Warning |
| Warn mode | Info |

### Resource Limits

| Condition | Severity |
|-----------|----------|
| Usage >= 90% | Critical |
| Usage >= 75% | Warning |
| Usage < 75% | Info |

### Missing Resources

| Condition | Severity |
|-----------|----------|
| Required for core functionality | Critical |
| Recommended (monitoring, scaling) | Warning |
| Nice to have | Info |

---

## Severity Override

Platform admins can override default severity via ConstraintProfile:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: strict-quotas
spec:
  gvr:
    group: ""
    version: v1
    resource: resourcequotas
  adapter: resourcequota
  severity: Critical  # Override: all quotas are Critical
```

---

## Filtering by Severity

### CLI

```bash
# Critical only
potoo query -n my-namespace --severity Critical

# Warning and above
potoo query -n my-namespace --severity Warning
potoo query -n my-namespace --severity Critical
```

### MCP Tool

```json
{
  "tool": "potoo_query",
  "params": {
    "namespace": "my-namespace",
    "severity": "Critical"
  }
}
```

### kubectl

```bash
# Count by severity
kubectl get cr constraints -n my-namespace -o json | \
  jq '.status | {critical: .criticalCount, warning: .warningCount, info: .infoCount}'

# Filter constraints
kubectl get cr constraints -n my-namespace -o json | \
  jq '.status.constraints[] | select(.severity == "Critical")'
```

---

## Notification Thresholds

Slack and webhook notifications can be filtered by severity:

```yaml
# Helm values
notifications:
  slack:
    enabled: true
    minSeverity: Critical  # Only Critical alerts

# NotificationPolicy
spec:
  channels:
    slack:
      minSeverity: Warning  # Critical + Warning
```

| minSeverity Setting | Notifications Sent |
|---------------------|-------------------|
| `Critical` | Critical only |
| `Warning` | Critical + Warning |
| `Info` | All severities |

---

## Status Command Summary

The `potoo status` command shows severity breakdown:

```bash
$ potoo status

NAMESPACE         TOTAL   CRITICAL   WARNING   INFO
production        5       2          2         1
staging           3       1          1         1
development       8       0          4         4
---
Total: 16 constraints across 3 namespaces
Critical: 3, Warning: 7, Info: 6
```

---

## Severity in Reports

ConstraintReport includes severity counts:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintReport
metadata:
  name: constraints
  namespace: production
status:
  constraintCount: 5
  criticalCount: 2
  warningCount: 2
  infoCount: 1
```

kubectl columns show this summary:

```bash
$ kubectl get cr -A

NAMESPACE    NAME          CONSTRAINTS   CRITICAL   WARNING   AGE
production   constraints   5             2          2         24h
staging      constraints   3             1          1         24h
```

---

## Recommended Actions by Severity

### Critical
1. Investigate immediately
2. Check recent deployments for correlation
3. Use `potoo explain` to diagnose
4. Apply remediation or request exception

### Warning
1. Schedule review within sprint
2. Monitor for escalation to Critical
3. Address quota issues before hitting limits
4. Create missing resources

### Info
1. Review during maintenance windows
2. Consider implementing recommendations
3. No urgent action required
