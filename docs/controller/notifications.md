---
layout: default
title: Notifications
parent: Controller
nav_order: 3
---

# Notifications
{: .no_toc }

Configure how Potoo notifies developers about constraints.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Potoo delivers constraint information through multiple channels:

| Channel | Purpose | Enabled By Default |
|---------|---------|-------------------|
| Kubernetes Events | Real-time alerts on workloads | Yes |
| ConstraintReport CRDs | Structured data for tooling | Yes |
| Workload Annotations | Labels for kubectl/UIs | Yes |
| Slack | Team alerting | No |
| Webhook | Custom integrations | No |

---

## Kubernetes Events

Events are created on affected workloads when constraints are discovered or change.

### Configuration

```yaml
notifications:
  kubernetesEvents: true
  rateLimitPerMinute: 100  # Per namespace
```

### Event Format

```yaml
apiVersion: v1
kind: Event
metadata:
  name: my-deployment.constraint-discovered
  namespace: my-namespace
type: Warning
reason: ConstraintDiscovered
message: |
  NetworkPolicy 'restrict-egress' restricts egress from this workload.
  Allowed ports: 443, 8443. Contact platform-team@company.com for exceptions.
involvedObject:
  apiVersion: apps/v1
  kind: Deployment
  name: my-deployment
```

### Viewing Events

```bash
# Events on a specific workload
kubectl describe deployment my-deployment

# All constraint events in namespace
kubectl get events -n my-namespace --field-selector reason=ConstraintDiscovered
```

---

## ConstraintReport CRDs

A ConstraintReport is created per namespace containing all constraints.

### Configuration

```yaml
notifications:
  constraintReports: true
```

### Report Format

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

  constraints:
    - name: restrict-egress
      type: NetworkEgress
      severity: Critical
      message: "Egress restricted to ports 443, 8443"
      source: NetworkPolicy
      lastSeen: "2024-01-15T10:30:00Z"

  machineReadable:
    schemaVersion: "1"
    detailLevel: summary
    constraints:
      - uid: abc123
        name: restrict-egress
        constraintType: NetworkEgress
        severity: Critical
        effect: deny
        sourceRef:
          apiVersion: networking.k8s.io/v1
          kind: NetworkPolicy
          name: restrict-egress
          namespace: my-namespace
        remediation:
          summary: "Request network policy exception"
          steps:
            - type: manual
              description: "Contact platform team"
              contact: "platform-team@company.com"
        tags: [network, egress]
```

### Viewing Reports

```bash
# List all reports
kubectl get constraintreports -A

# View specific report
kubectl get constraintreport constraints -n my-namespace -o yaml

# JSON output for tooling
kubectl get constraintreport constraints -n my-namespace -o json | jq '.status.machineReadable'
```

---

## Workload Annotations

Potoo annotates affected workloads with constraint summaries.

### Configuration

```yaml
workloadAnnotations:
  enabled: true
  kinds:
    - Deployment
    - StatefulSet
    - DaemonSet
  maxConstraintsPerWorkload: 20
```

### Tuning

The annotator supports debounce and cache tuning to control how often workload PATCHes are issued:

| Flag / Helm Value | Default | Description |
|---|---|---|
| `--annotator-debounce` / `controller.annotatorDebounce` | `30s` | Minimum time between annotation PATCHes for the same workload |
| `--annotator-cache-ttl` / `controller.annotatorCacheTTL` | `30s` | How long namespace workload lists are cached before re-fetching |

Lower values give faster feedback but increase API server load. For E2E or development environments, values as low as `5s`/`3s` are practical.

### Annotation Format

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    potoo.io/constraints: |
      [
        {"name":"restrict-egress","type":"NetworkEgress","severity":"Critical"},
        {"name":"compute-quota","type":"ResourceLimit","severity":"Warning"}
      ]
    potoo.io/constraint-count: "2"
    potoo.io/critical-count: "1"
    potoo.io/last-updated: "2024-01-15T10:30:00Z"
```

### Viewing Annotations

```bash
# View constraint annotations
kubectl get deployment my-app -o jsonpath='{.metadata.annotations.potoo\.io/constraints}' | jq

# List workloads with critical constraints
kubectl get deployments -A -o json | jq -r '
  .items[] |
  select(.metadata.annotations["potoo.io/critical-count"] | tonumber > 0) |
  "\(.metadata.namespace)/\(.metadata.name)"
'
```

---

## Slack Integration

Send alerts to Slack channels.

### Configuration

```yaml
notifications:
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minSeverity: Critical  # Only Critical alerts
```

### Creating a Webhook

1. Go to [Slack API](https://api.slack.com/apps)
2. Create a new app or select existing
3. Enable "Incoming Webhooks"
4. Add webhook to desired channel
5. Copy webhook URL

### Message Format

```
:warning: *Constraint Discovered*

*Namespace:* production
*Workload:* api-server
*Constraint:* restrict-egress (NetworkPolicy)
*Severity:* Critical
*Effect:* Egress restricted to ports 443, 8443

*Remediation:* Contact platform-team@company.com for exceptions
```

### Severity Filtering

| minSeverity | Notifications Sent |
|-------------|-------------------|
| `Critical` | Only Critical |
| `Warning` | Critical + Warning |
| `Info` | All constraints |

---

## Generic Webhook

Send JSON payloads to any HTTP endpoint via POST. Webhook notifications are dispatched asynchronously through a bounded worker pool, with automatic retry on transient failures.

### Configuration

**Helm values:**

```yaml
notifications:
  webhook:
    enabled: true
    url: "https://your-service.example.com/potoo-webhook"
    timeoutSeconds: 10        # HTTP request timeout (default: 10)
    insecureSkipVerify: false  # Skip TLS certificate verification (default: false)
    minSeverity: Warning       # Minimum severity to notify: Critical, Warning, Info
```

**CLI flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webhook-url` | _(empty)_ | URL for generic webhook notifications (HTTP POST). Webhook is disabled when empty. |
| `--webhook-timeout` | `10` | HTTP request timeout in seconds |
| `--webhook-insecure-skip-verify` | `false` | Disable TLS certificate verification (insecure) |
| `--webhook-min-severity` | `Warning` | Minimum severity for webhook notifications |

### Payload Format

Each webhook POST sends a `WebhookEnvelope` containing the full constraint notification:

```json
{
  "type": "potoo.constraint.notification",
  "schemaVersion": "1",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "schemaVersion": "1",
    "constraintUid": "abc123",
    "constraintName": "restrict-egress",
    "constraintNamespace": "my-namespace",
    "constraintType": "NetworkEgress",
    "severity": "Critical",
    "effect": "deny",
    "sourceGvr": "networking.k8s.io/v1/networkpolicies",
    "sourceKind": "NetworkPolicy",
    "workloadKind": "Deployment",
    "workloadName": "api-server",
    "workloadNamespace": "production",
    "summary": "Outbound network traffic is restricted by a network policy",
    "remediation": {
      "summary": "Request network policy exception",
      "steps": [
        {
          "type": "manual",
          "description": "Contact platform team",
          "contact": "platform-team@company.com"
        }
      ]
    },
    "tags": ["network", "egress"],
    "detailLevel": "summary",
    "observedAt": "2024-01-15T10:30:00Z"
  }
}
```

The `data` field uses the same `EventStructuredData` schema as Kubernetes Event annotations and MCP query responses.

### Privacy Scoping

Webhook payloads use **summary-level** privacy scoping by default (matching developer-facing Events). This means:

- Constraint names are redacted for cross-namespace constraints
- Cross-namespace details are not included
- Generic remediation guidance is provided

See [Privacy Model](/docs/reference/privacy/) for details on what each level includes.

### Authentication

**Bearer token from Kubernetes Secret (recommended):**

```yaml
notifications:
  webhook:
    enabled: true
    url: "https://your-service.example.com/potoo-webhook"
    authSecretRef:
      name: webhook-auth-token
      key: token
```

The controller reads the bearer token from the referenced Secret and sends it as an `Authorization: Bearer <token>` header.

**CLI flag (for development):**

When using CLI flags directly (without a NotificationPolicy CRD), the auth token is not yet supported. Use the CRD-based configuration or a service mesh sidecar for authentication.

### Retry Behavior

| Property | Value |
|----------|-------|
| Max retries | 2 (3 attempts total) |
| Backoff | Linear: 1s, 2s |
| Retryable errors | HTTP 5xx, connection errors |
| Non-retryable errors | HTTP 4xx (client errors) |
| Worker pool | 3 concurrent workers |
| Buffer size | 100 pending notifications |

When the send buffer is full, new notifications are dropped with a `dropped` metric increment.

### Observability

Prometheus metrics are exposed for webhook monitoring:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `potoo_webhook_send_total` | Counter | `status` | Total send attempts (`success`, `error`, `retry`, `dropped`) |
| `potoo_webhook_send_duration_seconds` | Histogram | `status` | HTTP request duration (`success`, `error`) |

### Severity Filtering

| minSeverity | Notifications Sent |
|-------------|-------------------|
| `Critical` | Only Critical |
| `Warning` | Critical + Warning |
| `Info` | All constraints |

---

## Deduplication

Prevent notification spam for unchanged constraints.

### Configuration

```yaml
notifications:
  deduplication:
    enabled: true
    suppressDuplicateMinutes: 60
```

### Behavior

- First notification: Always sent
- Subsequent: Suppressed if constraint unchanged
- After timeout: Re-sent if still present
- On change: Immediately sent

---

## Rate Limiting

Prevent overwhelming notification channels.

### Configuration

```yaml
notifications:
  rateLimitPerMinute: 100
```

Rate limit is per namespace. When exceeded:
- Events continue (K8s handles backpressure)
- Slack/Webhook queued and sent later
- ConstraintReports always updated

---

## Privacy and Detail Levels

Notifications are scoped based on the audience.

### Configuration

```yaml
privacy:
  defaultDeveloperDetailLevel: summary
  showCrossNamespacePolicyNames: false
  showPortNumbers: false
  remediationContact: "platform-team@company.com"
```

### What Each Level Shows

| Level | Constraint Name | Ports | Cross-NS Details |
|-------|----------------|-------|------------------|
| `summary` | Same NS only | No | No |
| `detailed` | Same NS only | Yes | No |
| `full` | All | Yes | Yes |

### NotificationPolicy CRD

For fine-grained control over notification routing, create a NotificationPolicy. The controller watches these resources and dynamically routes constraint notifications to the configured channels.

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: default
spec:
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    showAffectedPorts: false
    showRemediationContact: true
    contact: "platform-team@company.com"
    maxDetailLevel: summary

  platformAdminScope:
    showConstraintName: "all"
    showAffectedPorts: true
    maxDetailLevel: full

  platformAdminRoles:
    - cluster-admin
    - platform-admin

  channels:
    webhook:
      enabled: true
      url: "https://your-service.example.com/potoo-webhook"
      minSeverity: Warning
      authSecretRef:
        name: webhook-auth-token
        key: token
    slack:
      enabled: true
      webhookUrl: "https://hooks.slack.com/services/XXX"
      minSeverity: Critical
```

### Routing Behavior

- **Watch-based**: Policy CRUD is reflected without controller restart.
- **Multiple policies**: All matching policies receive notifications. Each policy's configured channels independently receive constraint alerts that meet their severity threshold.
- **Detail level**: The alphabetically-first policy's `developerScope.maxDetailLevel` determines the detail level for K8s Events and ConstraintReports. When no policies exist, the default is `summary`.
- **CLI fallback**: The `--webhook-url` CLI flag continues to work as a static fallback sender alongside CRD-configured senders.
- **Auth tokens**: The `authSecretRef` reads a bearer token from a K8s Secret in the controller's namespace (set via `POD_NAMESPACE` env var, defaults to `potoo-system`).
- **Slack**: Slack channel support is planned but not yet implemented. Enabling Slack in a policy logs a warning.

---

## Troubleshooting

### Events Not Appearing

```bash
# Check controller can create events
kubectl auth can-i create events --as=system:serviceaccount:potoo-system:potoo-controller

# Check controller logs
kubectl logs -n potoo-system -l app=potoo-controller | grep "event"
```

### Slack Not Receiving Messages

```bash
# Test webhook manually
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test message"}' \
  https://hooks.slack.com/services/XXX/YYY/ZZZ

# Check controller logs
kubectl logs -n potoo-system -l app=potoo-controller | grep "slack"
```

### Cluster-Scoped Constraints

Cluster-scoped constraints (e.g., `ValidatingWebhookConfiguration`, Gatekeeper `ConstraintTemplate` instances) affect all namespaces. When a cluster-scoped constraint has explicit `AffectedNamespaces`, only those namespaces are updated. When it has none, Potoo triggers a cluster-wide reconciliation: it lists all namespaces and updates the ConstraintReport and workload annotations in each.

This applies to both ConstraintReport reconciliation and workload annotation. Debounce timers prevent excessive reconciliation from rapid cluster-scoped changes.

### Report Reconciler Tuning

The ConstraintReport reconciler uses a worker pool and per-namespace debounce to batch updates:

| Flag / Helm Value | Default | Description |
|---|---|---|
| `--report-debounce` / `controller.reportDebounce` | `10s` | Minimum time between ConstraintReport reconciles for the same namespace |
| `--report-workers` / `controller.reportWorkers` | `3` | Number of concurrent workers processing ConstraintReport reconciles |

Increasing `reportWorkers` helps clusters with many namespaces. Lowering `reportDebounce` reduces latency but increases API server writes.

### ConstraintReports Not Updating

```bash
# Check CRD exists
kubectl get crd constraintreports.potoo.io

# Check controller logs
kubectl logs -n potoo-system -l app=potoo-controller | grep "report"

# Force rescan
kubectl rollout restart deployment -n potoo-system potoo-controller
```
