# Potoo Helm Chart

Automatic constraint discovery and developer notification for Kubernetes.

## Description

Potoo is a Kubernetes operator that discovers all policies, constraints, quotas, and requirements across your cluster — regardless of which policy engine created them — and notifies developers when those constraints block their workloads.

This chart deploys:
- **Controller** — Discovers and indexes constraints, dispatches notifications
- **Admission Webhook** — Real-time deploy-time warnings (always fail-open)
- **CRDs** — ConstraintReport, ConstraintProfile, NotificationPolicy

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- (Optional) cert-manager for webhook TLS certificate management

## Installation

```bash
helm repo add potoo https://potoo.io/charts
helm install potoo potoo/potoo \
  -n potoo-system \
  --create-namespace
```

Or install directly from OCI registry (Helm 3.8+):

```bash
helm install potoo oci://ghcr.io/potooio/charts/potoo \
  -n potoo-system \
  --create-namespace
```

### Install with custom values

```bash
helm install potoo potoo/potoo \
  -n potoo-system \
  --create-namespace \
  -f values.yaml
```

### Verify

```bash
kubectl get pods -n potoo-system
kubectl get crd | grep potoo
```

## Values

The table below lists the most commonly configured parameters. See the [full configuration reference](https://github.com/potooio/potoo/blob/master/docs/controller/configuration.md) for all options, or inspect [`values.yaml`](values.yaml) directly.

### Controller

| Parameter | Default | Description |
|-----------|---------|-------------|
| `controller.replicas` | `2` | Number of controller replicas |
| `controller.leaderElect` | `true` | Enable leader election for HA |
| `controller.rescanInterval` | `5m` | How often to scan for new CRDs |
| `controller.image.repository` | `ghcr.io/potooio/potoo` | Controller image |
| `controller.image.tag` | `""` (appVersion) | Image tag |
| `controller.resources.requests.cpu` | `100m` | CPU request |
| `controller.resources.requests.memory` | `256Mi` | Memory request |
| `controller.annotatorDebounce` | `30s` | Minimum time between annotation PATCHes for the same workload |
| `controller.annotatorCacheTTL` | `30s` | How long namespace workload lists are cached before re-fetching |
| `controller.reportDebounce` | `10s` | Minimum time between ConstraintReport reconciles for the same namespace |
| `controller.reportWorkers` | `3` | Number of concurrent workers processing ConstraintReport reconciles |

### Admission Webhook

| Parameter | Default | Description |
|-----------|---------|-------------|
| `admissionWebhook.enabled` | `true` | Deploy admission webhook |
| `admissionWebhook.replicas` | `2` | Webhook replicas |
| `admissionWebhook.failurePolicy` | `Ignore` | **Must always be `Ignore`** — never set to `Fail` |
| `admissionWebhook.timeoutSeconds` | `5` | Webhook timeout |
| `admissionWebhook.certManagement` | `self-signed` | TLS cert strategy (`self-signed` or `cert-manager`) |
| `admissionWebhook.pdb.enabled` | `true` | Enable PodDisruptionBudget |

### Adapters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `adapters.networkpolicy.enabled` | `true` | NetworkPolicy adapter (native K8s) |
| `adapters.resourcequota.enabled` | `true` | ResourceQuota adapter (native K8s) |
| `adapters.webhook.enabled` | `true` | WebhookConfiguration adapter (native K8s) |
| `adapters.cilium.enabled` | `auto` | Cilium adapter (`auto`, `enabled`, `disabled`) |
| `adapters.gatekeeper.enabled` | `auto` | Gatekeeper/OPA adapter |
| `adapters.kyverno.enabled` | `auto` | Kyverno adapter |
| `adapters.istio.enabled` | `auto` | Istio adapter |
| `adapters.prometheus.enabled` | `auto` | Prometheus adapter |

### Discovery

| Parameter | Default | Description |
|-----------|---------|-------------|
| `discovery.additionalPolicyGroups` | `[]` | Additional API groups to treat as policy sources (beyond built-in groups) |
| `discovery.additionalPolicyNameHints` | `[]` | Additional resource name substrings for heuristic policy detection |
| `discovery.checkCRDAnnotations` | `true` | Check CRDs for `potoo.io/is-policy` annotation during discovery scan |

### Notifications

| Parameter | Default | Description |
|-----------|---------|-------------|
| `notifications.kubernetesEvents` | `true` | Create K8s Events on affected workloads |
| `notifications.constraintReports` | `true` | Create ConstraintReport CRDs per namespace |
| `notifications.rateLimitPerMinute` | `100` | Max events per minute per namespace |
| `notifications.webhook.enabled` | `false` | Enable generic webhook notifications (HTTP POST) |
| `notifications.webhook.url` | `""` | Webhook endpoint URL |
| `notifications.webhook.timeoutSeconds` | `10` | HTTP request timeout (1-60) |
| `notifications.webhook.insecureSkipVerify` | `false` | Disable TLS verification (insecure) |
| `notifications.webhook.minSeverity` | `Warning` | Minimum severity for webhooks |
| `notifications.webhook.authTokenSecretRef.name` | `""` | Secret name containing auth token |
| `notifications.webhook.authTokenSecretRef.key` | `token` | Key within the auth Secret |
| `notifications.slack.enabled` | `false` | Enable Slack notifications |
| `notifications.slack.webhookUrl` | `""` | Slack incoming webhook URL |
| `notifications.slack.minSeverity` | `Critical` | Minimum severity for Slack alerts |
| `notifications.deduplication.enabled` | `true` | Suppress duplicate notifications |

### Privacy

| Parameter | Default | Description |
|-----------|---------|-------------|
| `privacy.defaultDeveloperDetailLevel` | `summary` | Detail level: `summary`, `detailed`, `full` |
| `privacy.showCrossNamespacePolicyNames` | `false` | Show constraint names from other namespaces |
| `privacy.showPortNumbers` | `false` | Show specific port numbers in developer notifications |
| `privacy.remediationContact` | `""` | Default contact for remediation hints |

### Optional Features

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hubble.enabled` | `false` | Enable Cilium Hubble flow integration |
| `hubble.relayAddress` | `hubble-relay.kube-system.svc:4245` | Hubble Relay address |
| `mcp.enabled` | `false` | Enable MCP server for AI agent integration |
| `mcp.port` | `8090` | MCP server port |
| `requirements.enabled` | `true` | Enable missing resource detection |
| `requirements.debounceSeconds` | `120` | Debounce period before alerting |
| `monitoring.serviceMonitor.enabled` | `false` | Create Prometheus ServiceMonitor |
| `apiServer.enabled` | `true` | Enable HTTP API server |

### Infrastructure

| Parameter | Default | Description |
|-----------|---------|-------------|
| `rbac.create` | `true` | Create ClusterRole and ClusterRoleBinding |
| `rbac.workloadPatch` | `true` | Grant `patch` on Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, and Pods for workload annotation |
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `serviceAccount.name` | `""` | ServiceAccount name (auto-generated if empty) |
| `workloadAnnotations.enabled` | `true` | Annotate workloads with constraint summaries |

## Examples

### Enable webhook notifications

```yaml
notifications:
  webhook:
    enabled: true
    url: "https://hooks.example.com/potoo"
    timeoutSeconds: 10
    minSeverity: Warning
    # Optional: authenticate via Bearer token from a Secret
    authTokenSecretRef:
      name: "potoo-webhook-token"
      key: "token"
```

### Enable Slack notifications

```yaml
notifications:
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minSeverity: Critical
```

### Enable MCP server for AI agents

```yaml
mcp:
  enabled: true
  port: 8090
  transport: sse
  authentication:
    method: kubernetes-sa
```

### Enable Hubble integration

```yaml
hubble:
  enabled: true
  relayAddress: hubble-relay.kube-system.svc:4245
```

### Custom policy discovery

Extend Potoo's heuristic policy detection to find CRDs from your own API groups or with custom naming patterns:

```yaml
discovery:
  # API groups to scan beyond the built-in list (networking.k8s.io, cilium.io,
  # gatekeeper.sh, kyverno.io, security.istio.io, etc.)
  additionalPolicyGroups:
    - "policy.company.com"
    - "security.internal.io"

  # Resource name substrings that hint a CRD is policy-related.
  # Built-in hints include: policy, constraint, rule, quota, limit, webhook.
  additionalPolicyNameHints:
    - "compliance"
    - "restriction"
    - "firewall"

  # Discover CRDs annotated with potoo.io/is-policy: "true"
  checkCRDAnnotations: true
```

### cert-manager webhook certificates

```yaml
admissionWebhook:
  certManagement: cert-manager
  certManager:
    # Option 1: Simple issuer reference by name
    issuerName: "letsencrypt-prod"
    issuerKind: ClusterIssuer  # or "Issuer" for namespace-scoped

    # Option 2: Full issuer reference (overrides issuerName/issuerKind)
    # issuerRef:
    #   name: "custom-issuer"
    #   kind: "ClusterIssuer"
    #   group: "cert-manager.io"

    duration: 8760h     # 1 year
    renewBefore: 720h   # 30 days
```

When `issuerRef` is set (non-empty object), it takes precedence over `issuerName` and `issuerKind`.

### Production configuration

```yaml
controller:
  replicas: 2
  leaderElect: true
  resources:
    requests:
      cpu: 200m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi

admissionWebhook:
  enabled: true
  replicas: 2
  failurePolicy: Ignore
  certManagement: cert-manager

notifications:
  kubernetesEvents: true
  constraintReports: true
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minSeverity: Critical
  deduplication:
    enabled: true

privacy:
  defaultDeveloperDetailLevel: summary
  remediationContact: "platform-team@company.com"

monitoring:
  serviceMonitor:
    enabled: true
```

## Uninstall

```bash
helm uninstall potoo -n potoo-system

# Remove CRDs (optional — deletes all ConstraintReports)
kubectl delete crd constraintreports.potoo.io
kubectl delete crd constraintprofiles.potoo.io
kubectl delete crd notificationpolicies.potoo.io

kubectl delete namespace potoo-system
```

## Links

- [Full Configuration Reference](https://github.com/potooio/potoo/blob/master/docs/controller/configuration.md)
- [Getting Started](https://github.com/potooio/potoo/blob/master/docs/getting-started/quickstart.md)
- [Architecture](https://github.com/potooio/potoo/blob/master/docs/ARCHITECTURE.md)
- [Privacy Model](https://github.com/potooio/potoo/blob/master/docs/PRIVACY_MODEL.md)
- [Source Code](https://github.com/potooio/potoo)
