---
layout: default
title: ConstraintReport
parent: CRDs
nav_order: 1
---

# ConstraintReport
{: .no_toc }

Per-namespace summary of all constraints affecting workloads.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

ConstraintReport is a namespace-scoped resource that contains all discovered constraints affecting workloads in that namespace. The controller creates and updates these automatically.

**API Version:** `potoo.io/v1alpha1`

**Short Name:** `cr`

**Scope:** Namespaced

---

## Usage

```bash
# List all reports
kubectl get constraintreports -A

# View report for a namespace
kubectl get cr -n my-namespace

# View full details
kubectl get cr constraints -n my-namespace -o yaml

# View machine-readable section
kubectl get cr constraints -n my-namespace -o json | jq '.status.machineReadable'
```

---

## Spec

ConstraintReport has no `spec` field—it is read-only and populated by the controller.

---

## Status

All data is in the `status` field:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintReport
metadata:
  name: constraints
  namespace: my-namespace
status:
  constraintCount: 3
  criticalCount: 1
  warningCount: 1
  infoCount: 1
  lastUpdated: "2024-01-15T10:30:00Z"

  # Human-readable entries (for kubectl display)
  constraints:
    - name: restrict-egress
      type: NetworkEgress
      severity: Critical
      affectedWorkloads:
        - api-server
        - worker
      message: "Egress restricted to ports 443, 8443"
      source: NetworkPolicy
      lastSeen: "2024-01-15T10:30:00Z"

  # Machine-readable section (for tooling/agents)
  machineReadable:
    schemaVersion: "1"
    generatedAt: "2024-01-15T10:30:00Z"
    detailLevel: summary
    constraints: [...]
    missingResources: [...]
    tags: [...]
```

---

## Status Fields

### Top-Level Counts

| Field | Type | Description |
|-------|------|-------------|
| `constraintCount` | int | Total constraints affecting this namespace |
| `criticalCount` | int | Critical severity count |
| `warningCount` | int | Warning severity count |
| `infoCount` | int | Info severity count |
| `lastUpdated` | Time | Last reconciliation timestamp |

### constraints[]

Human-readable entries for kubectl display:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Constraint name (may be redacted) |
| `type` | enum | NetworkIngress, NetworkEgress, Admission, ResourceLimit, MeshPolicy, MissingResource, Unknown |
| `severity` | enum | Critical, Warning, Info |
| `affectedWorkloads` | []string | Workload names in this namespace |
| `message` | string | Human-readable summary |
| `source` | string | Policy engine type |
| `lastSeen` | Time | Last observation time |

---

## Machine-Readable Section

The `machineReadable` section contains structured data optimized for programmatic consumption:

```yaml
machineReadable:
  schemaVersion: "1"
  generatedAt: "2024-01-15T10:30:00Z"
  detailLevel: summary

  constraints:
    - uid: "abc123"
      name: "restrict-egress"
      constraintType: "NetworkEgress"
      severity: "Critical"
      effect: "deny"
      sourceRef:
        apiVersion: "networking.k8s.io/v1"
        kind: "NetworkPolicy"
        name: "restrict-egress"
        namespace: "my-namespace"
      affectedWorkloads:
        - kind: "Deployment"
          name: "api-server"
          matchReason: "Label selector match"
      remediation:
        summary: "Request network policy exception"
        steps:
          - type: "manual"
            description: "Contact platform team"
            contact: "platform-team@company.com"
            requiresPrivilege: "developer"
      metrics: null
      tags:
        - "network"
        - "egress"
      lastObserved: "2024-01-15T10:30:00Z"

  missingResources:
    - expectedKind: "ServiceMonitor"
      expectedAPIVersion: "monitoring.coreos.com/v1"
      reason: "Workload has a port named metrics or http-metrics but no Prometheus monitor targets it"
      severity: "Warning"
      forWorkload:
        kind: "Deployment"
        name: "api-server"
      remediation:
        summary: "Create ServiceMonitor"
        steps: [...]

  tags:
    - "network"
    - "egress"
    - "admission"
```

### MachineReadableReport Fields

| Field | Type | Description |
|-------|------|-------------|
| `schemaVersion` | string | Schema version for compatibility |
| `generatedAt` | Time | When this section was rendered |
| `detailLevel` | enum | summary, detailed, full |
| `constraints` | []MachineConstraintEntry | Structured constraint list |
| `missingResources` | []MissingResourceEntry | Missing companion resources |
| `tags` | []string | All tags across all constraints |

### MachineConstraintEntry Fields

| Field | Type | Description |
|-------|------|-------------|
| `uid` | string | Stable identifier |
| `name` | string | Constraint name |
| `constraintType` | enum | Constraint type |
| `severity` | enum | Severity level |
| `effect` | string | deny, restrict, warn, audit, limit |
| `sourceRef` | ObjectReference | Reference to source K8s object |
| `affectedWorkloads` | []WorkloadReference | Affected workloads |
| `remediation` | RemediationInfo | Structured remediation |
| `metrics` | map[string]ResourceMetric | Quota usage (ResourceLimit only) |
| `tags` | []string | Filtering tags |
| `lastObserved` | Time | Last observation |

### ObjectReference Fields

| Field | Type | Description |
|-------|------|-------------|
| `apiVersion` | string | API version of source |
| `kind` | string | Kubernetes kind |
| `name` | string | Resource name |
| `namespace` | string | Namespace (empty if cluster-scoped) |

### WorkloadReference Fields

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Workload kind (Deployment, etc.) |
| `name` | string | Workload name |
| `matchReason` | string | Why this workload matched |

### RemediationInfo Fields

| Field | Type | Description |
|-------|------|-------------|
| `summary` | string | One-line description |
| `steps` | []RemediationStep | Ordered remediation steps |

### RemediationStep Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | enum | manual, kubectl, annotation, yaml_patch, link |
| `description` | string | Step explanation |
| `command` | string | kubectl command (when type=kubectl) |
| `patch` | string | Patch command (when type=annotation) |
| `template` | string | YAML template (when type=yaml_patch) |
| `url` | string | Documentation URL (when type=link) |
| `contact` | string | Contact info (when type=manual) |
| `requiresPrivilege` | enum | developer, namespace-admin, cluster-admin |

### ResourceMetric Fields

| Field | Type | Description |
|-------|------|-------------|
| `hard` | string | Quota limit |
| `used` | string | Current usage |
| `unit` | string | Unit (cores, bytes, count) |
| `percentUsed` | float64 | Percentage used |

### MissingResourceEntry Fields

| Field | Type | Description |
|-------|------|-------------|
| `expectedKind` | string | Kind that should exist |
| `expectedAPIVersion` | string | API version |
| `reason` | string | Why expected |
| `severity` | enum | Warning, Critical |
| `forWorkload` | WorkloadReference | Which workload needs it |
| `remediation` | RemediationInfo | How to create it |

See [Missing Resource Detection](/docs/controller/missing-resources/) for the full list of built-in detection rules.

---

## kubectl Print Columns

When viewing with `kubectl get`:

```bash
kubectl get cr -n my-namespace
```

Output:
```
NAME          CONSTRAINTS   CRITICAL   WARNING   AGE
constraints   3             1          1         24h
```

---

## Example: Full Report

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintReport
metadata:
  name: constraints
  namespace: production
status:
  constraintCount: 3
  criticalCount: 1
  warningCount: 1
  infoCount: 1
  lastUpdated: "2024-01-15T10:30:00Z"

  constraints:
    - name: restrict-egress
      type: NetworkEgress
      severity: Critical
      affectedWorkloads: [api-server, worker]
      message: "Egress restricted to ports 443, 8443"
      source: NetworkPolicy
      lastSeen: "2024-01-15T10:30:00Z"

    - name: compute-quota
      type: ResourceLimit
      severity: Warning
      affectedWorkloads: []
      message: "CPU usage at 78% of quota"
      source: ResourceQuota
      lastSeen: "2024-01-15T10:30:00Z"

    - name: require-labels
      type: Admission
      severity: Info
      affectedWorkloads: []
      message: "Pods must have team label (audit mode)"
      source: Gatekeeper
      lastSeen: "2024-01-15T10:30:00Z"

  machineReadable:
    schemaVersion: "1"
    generatedAt: "2024-01-15T10:30:00Z"
    detailLevel: summary

    constraints:
      - uid: "uid-1"
        name: "restrict-egress"
        constraintType: "NetworkEgress"
        severity: "Critical"
        effect: "deny"
        sourceRef:
          apiVersion: "networking.k8s.io/v1"
          kind: "NetworkPolicy"
          name: "restrict-egress"
          namespace: "production"
        affectedWorkloads:
          - kind: "Deployment"
            name: "api-server"
        remediation:
          summary: "Request network policy exception"
          steps:
            - type: "manual"
              description: "Contact platform team"
              contact: "platform-team@company.com"
              requiresPrivilege: "developer"
        tags: ["network", "egress"]
        lastObserved: "2024-01-15T10:30:00Z"

      - uid: "uid-2"
        name: "compute-quota"
        constraintType: "ResourceLimit"
        severity: "Warning"
        effect: "limit"
        sourceRef:
          apiVersion: "v1"
          kind: "ResourceQuota"
          name: "compute-quota"
          namespace: "production"
        remediation:
          summary: "Request quota increase"
          steps:
            - type: "kubectl"
              description: "Check current usage"
              command: "kubectl get resourcequota -n production"
        metrics:
          cpu:
            hard: "4"
            used: "3.12"
            unit: "cores"
            percentUsed: 78.0
        tags: ["quota", "cpu"]
        lastObserved: "2024-01-15T10:30:00Z"

    missingResources: []
    tags: ["network", "egress", "quota", "cpu", "admission"]
```

---

## Lifecycle

1. **Created**: When first constraint affects the namespace
2. **Updated**: On constraint changes (typically within 30 seconds)
3. **Preserved**: Reports persist even if controller restarts
4. **Deleted**: Only when namespace is deleted

The controller reconciles reports continuously. Changes trigger:
- Report update
- Kubernetes Event (if enabled)
- Slack/webhook notification (if enabled)
