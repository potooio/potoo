---
layout: default
title: Missing Resources
parent: Controller
nav_order: 4
---

# Missing Resource Detection
{: .no_toc }

Detect companion resources that should exist based on workload configuration.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Missing resource detection identifies companion Kubernetes resources that *should* exist based on a workload's annotations, ports, or namespace labels but don't. Unlike adapters (which parse existing policy objects), requirement rules reason about the *absence* of expected resources.

For example, a Deployment that exposes a port named `metrics` conventionally needs a `ServiceMonitor` so Prometheus can scrape it. If no matching ServiceMonitor exists, Potoo flags the gap.

Results surface in two places:

- **MCP pre-check** (`potoo_check` tool) -- returns `missing_prerequisites` immediately, with no debounce delay.
- **ConstraintReport** (`status.machineReadable.missingResources`) -- uses the evaluator's debounce window (default 120 seconds) to avoid false positives during rolling deployments.

---

## Built-in Rules

| Rule | Trigger Condition | Expected Resource | Severity |
|------|-------------------|-------------------|----------|
| `prometheus-monitor` | Port named `metrics` or `http-metrics` | ServiceMonitor or PodMonitor | Warning |
| `istio-routing` | Annotation `sidecar.istio.io/status` | VirtualService or DestinationRule | Warning |
| `istio-mtls` | Namespace label `istio-injection=enabled` | PeerAuthentication | Warning |
| `cert-issuer` | Annotation `cert-manager.io/cluster-issuer` or `cert-manager.io/issuer-name` | ClusterIssuer or Issuer | Critical |
| `crd-installed` | Metrics port, sidecar annotation, or cert-manager annotation present | Corresponding CRD exists in cluster | Warning |
| `annotation-requirements` | Annotation `potoo.io/requires` | Resources declared in the annotation | Warning |

---

## Rule Details

### prometheus-monitor

**Trigger:** Any container in the workload's pod template exposes a port named `metrics` or `http-metrics`.

**Detection logic:**

1. Scan `spec.template.spec.containers[].ports[].name` (or `spec.containers[].ports[].name` for bare Pods).
2. If a matching port is found, extract pod template labels (falling back to top-level labels).
3. Look for a `ServiceMonitor` (`monitoring.coreos.com/v1`) whose `spec.selector.matchLabels` matches the workload's labels.
4. If no ServiceMonitor matches, look for a `PodMonitor` (`monitoring.coreos.com/v1`) with matching labels.
5. If neither exists, emit a Warning constraint.

**Why it matters:** Without a ServiceMonitor or PodMonitor, Prometheus will not scrape the metrics endpoint even though the workload is configured to expose one.

### istio-routing

**Trigger:** Workload has the annotation `sidecar.istio.io/status` (injected by the Istio sidecar injector).

**Detection logic:**

1. List all `VirtualService` resources (`networking.istio.io/v1`) in the workload's namespace.
2. Check `spec.http[].route[].destination.host`, `spec.tcp[].route[].destination.host`, and `spec.tls[].route[].destination.host` for a host that matches the workload name.
3. Host matching accepts short names (`my-app`), namespaced form (`my-app.default`), and FQDN (`my-app.default.svc.cluster.local`).
4. If no VirtualService matches, check `DestinationRule` resources (`networking.istio.io/v1`) via `spec.host`.
5. If neither exists, emit a Warning constraint.

**Assumption:** The workload name matches its Service name (conventional Kubernetes pattern).

### istio-mtls

**Trigger:** The workload's namespace has the label `istio-injection=enabled`.

**Detection logic:**

1. List `PeerAuthentication` resources (`security.istio.io/v1`) in the workload's namespace.
2. If none exist, check for a mesh-wide PeerAuthentication in `istio-system` (one with no selector or empty `matchLabels`).
3. If the `istio-system` namespace is inaccessible (RBAC restrictions), the mesh-wide check is silently skipped -- this is non-fatal.
4. If no PeerAuthentication is found at either scope, emit a Warning constraint.

**Why it matters:** Without an explicit PeerAuthentication, mTLS behavior depends on Istio's mesh-wide defaults, which may not match the namespace's security requirements.

### cert-issuer

**Trigger:** Workload has either `cert-manager.io/cluster-issuer` or `cert-manager.io/issuer-name` annotation.

**Detection logic:**

1. If `cert-manager.io/cluster-issuer` is set, look up the named `ClusterIssuer` (`cert-manager.io/v1`, cluster-scoped).
2. If the ClusterIssuer exists, stop (cert-manager uses one issuer annotation at a time).
3. Otherwise, if `cert-manager.io/issuer-name` is set, look up the named `Issuer` (`cert-manager.io/v1`, namespace-scoped).
4. If the referenced issuer does not exist, emit a **Critical** constraint.

**Why this is Critical:** A missing issuer means cert-manager cannot issue or renew TLS certificates for the workload, which can cause TLS failures and outages.

---

## How Results Appear

### MCP Pre-check

The `potoo_check` tool returns missing resources in the `missing_prerequisites` array. Results are computed on demand with no debounce delay:

```json
{
  "missing_prerequisites": [
    {
      "expected_kind": "ServiceMonitor",
      "expected_api_version": "monitoring.coreos.com/v1",
      "reason": "Workload has a port named metrics or http-metrics but no Prometheus monitor targets it",
      "severity": "Warning",
      "for_workload": "production/Deployment/my-app"
    }
  ]
}
```

See [MCP Tools Reference](/docs/mcp/tools.html) for the full response schema.

### ConstraintReport

The report reconciler populates `status.machineReadable.missingResources` using the evaluator, which applies debounce:

```yaml
machineReadable:
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
```

See [ConstraintReport CRD](/docs/crds/constraintreport.html) for the full schema.

---

## Debounce Behavior

The evaluator debounces missing-resource alerts to prevent false positives during deployments. When resources are deployed via GitOps or CI/CD, the workload and its companion resources may arrive at slightly different times. Without debouncing, Potoo would briefly flag a missing resource that is actually in-flight.

| Setting | Default | Description |
|---------|---------|-------------|
| `requirements.debounceSeconds` | `120` | Seconds to wait before emitting a missing-resource constraint |

**How debouncing works:**

1. The evaluator tracks `workloadUID:ruleName` pairs with both a `firstSeen` and `lastSeen` timestamp.
2. A constraint is only emitted after the debounce window has elapsed since first detection, with the resource still absent.
3. If the resource appears before the window elapses, the tracking entry is cleared.
4. If the resource disappears again, a fresh debounce window starts.
5. Each evaluation refreshes `lastSeen`, so actively-detected missing resources are never evicted by cleanup. Stale entries (not seen for longer than 2x the debounce duration) are cleaned up periodically.

**MCP pre-check is not debounced.** The `potoo_check` tool evaluates rules directly against the current cluster state, making it suitable for pre-deploy validation where immediate feedback is desired.

---

## Configuration

```yaml
requirements:
  enabled: true
  debounceSeconds: 120
```

See [Configuration Reference](/docs/controller/configuration.html) for the full Helm values.

### crd-installed

**Trigger:** Workload has any of the trigger conditions from the other rules (metrics port, `sidecar.istio.io/status` annotation, `cert-manager.io/cluster-issuer` or `cert-manager.io/issuer-name` annotation).

**Detection logic:**

1. For each triggered condition, probe the corresponding CRD by issuing a namespace-scoped list via the API server.
2. If the API server returns a 404 (resource type not registered), the CRD is not installed.
3. Other errors (RBAC, network) are silently skipped to avoid false positives.
4. If the CRD is missing, emit a Warning constraint with the fully-qualified CRD name.

**Checked CRDs:**

| Trigger | CRD |
|---------|-----|
| Metrics port (`metrics` or `http-metrics`) | `servicemonitors.monitoring.coreos.com` |
| Istio sidecar annotation | `peerauthentications.security.istio.io` |
| cert-manager annotation | `clusterissuers.cert-manager.io` |

**Why it matters:** If the CRD itself is not installed, companion resource checks (ServiceMonitor, PeerAuthentication, ClusterIssuer) cannot function. This rule catches the higher-level misconfiguration — the entire operator or controller that manages those resources is absent from the cluster.

### annotation-requirements

**Trigger:** Workload has the annotation `potoo.io/requires` containing a YAML list of required companion resources.

**Annotation format:**

```yaml
annotations:
  potoo.io/requires: |
    - gvr: monitoring.coreos.com/v1/servicemonitors
      matching: app=my-service
      reason: "Prometheus won't scrape without a ServiceMonitor"
    - gvr: v1/services
      reason: "Workload needs a headless Service"
```

Each entry has:

| Field | Required | Description |
|-------|----------|-------------|
| `gvr` | Yes | GroupVersionResource in `group/version/resource` format. Core API resources use 2-part format: `v1/services`. |
| `matching` | No | Label selector (`key=value,key2=value2`). If set, at least one resource with these labels must exist. If omitted, any resource of the GVR type satisfies the requirement. |
| `reason` | No | Human-readable explanation included in the constraint summary. If omitted, a default message is generated. |

**Detection logic:**

1. Read the `potoo.io/requires` annotation value and parse as YAML.
2. For each entry, parse the GVR string and optional label selector.
3. List resources of the specified GVR in the workload's namespace.
4. If `matching` is set, filter by resource metadata labels.
5. If no matching resource exists, emit a Warning constraint.

**Error handling:**

- Invalid YAML annotation: logged as a warning by the evaluator, skipped.
- Invalid GVR format or label selector: logged as a warning, skipped.
- Cluster-scoped workloads (no namespace): silently skipped.

**Why it matters:** Built-in rules cover common scenarios (Prometheus, Istio, cert-manager), but teams often have project-specific companion resources. This annotation lets workload owners declare arbitrary dependencies without modifying the controller.

---

## Custom Requirements via Annotations

The `potoo.io/requires` annotation is the mechanism for declaring custom missing-resource checks. Workload owners add the annotation to their Deployments, StatefulSets, or other workload objects, and the `annotation-requirements` rule evaluates them automatically.

This replaces the need for custom rule registration — any GVR can be checked without code changes to the controller.
