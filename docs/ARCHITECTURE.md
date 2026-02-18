# Architecture

## Deployment Model

Potoo is deployed as a **Deployment-based operator**, not a DaemonSet. It needs to talk to the Kubernetes API server and optionally to Hubble Relay — both are network services. Running per-node would waste resources and require distributed coordination.

### Components

| Component | Kind | Replicas | Purpose |
|---|---|---|---|
| **Controller** | Deployment | 2 (leader-elected) | Core discovery, indexing, correlation, notification |
| **Admission Webhook** | Deployment | 2-3 | Deploy-time warnings (separate for failure isolation) |
| **CRDs** | CustomResourceDefinition | — | ConstraintProfile, NotificationPolicy, ConstraintReport |

The controller uses **leader election** via `controller-runtime`. One replica is active; the standby maintains warm informer caches for fast failover. The admission webhook is a separate Deployment because it's in the API server's critical path — if the controller crashes, the webhook should continue (or fail-open gracefully).

### Why Not a DaemonSet

DaemonSets are for node-level concerns (log collectors, CNI plugins, monitoring agents). Potoo operates at the API/control-plane level. Running N copies would mean N copies competing to process the same events. The one exception: if you want node-level eBPF flow capture supplementing Hubble, that *could* be a DaemonSet — but it's an optional, separate component for Phase 3+.

## Language: Go

Non-negotiable for this project:

- `client-go` and `controller-runtime` are the canonical Kubernetes libraries — first-party, battle-tested
- Every policy system we integrate with (Cilium, Gatekeeper, Kyverno, Istio) publishes Go API types
- Low memory footprint, fast startup, static binary, trivial container image
- The Kubernetes operator ecosystem is overwhelmingly Go; contributors can ramp up immediately

### Key Dependencies

```
k8s.io/client-go                    // API interaction, dynamic client, discovery
k8s.io/apimachinery                  // types, unstructured, schema
sigs.k8s.io/controller-runtime      // operator framework, leader election, health

github.com/cilium/cilium             // CiliumNetworkPolicy types (parse-only)
github.com/open-policy-agent/gatekeeper // Constraint types (parse-only)
github.com/kyverno/kyverno           // ClusterPolicy types (parse-only)
istio.io/client-go                   // Istio networking types (parse-only)

github.com/cilium/hubble             // Hubble flow observation (optional)
github.com/prometheus/client_golang  // /metrics endpoint
go.uber.org/zap                      // structured logging
```

**Important**: Policy type packages are imported for reference and testing, but runtime parsing uses `unstructured.Unstructured` with typed helpers. This prevents panics when CRDs aren't installed.

## Core Subsystems

### 1. Discovery Engine

The discovery engine automatically inventories every constraint-like resource in the cluster.

**Startup sequence:**
1. Call `discovery.ServerPreferredResources()` to enumerate all API resources
2. Match against known policy GVRs (hardcoded list of ~20 known types)
3. Apply heuristics to remaining CRDs (group/name contains "policy", "constraint", "rule", "quota", etc.)
4. Check for `potoo.io/is-policy: "true"` annotations on CRDs (admin override)
5. Load any `ConstraintProfile` CRDs that register additional types
6. Spin up dynamic informers for all discovered GVRs

**Periodic re-scan**: Every 5 minutes, re-run discovery to catch newly installed CRDs.

**Known policy GVRs** (bootstrapped at startup):
```
networking.k8s.io/v1/networkpolicies
cilium.io/v2/ciliumnetworkpolicies
cilium.io/v2/ciliumclusterwidenetworkpolicies
constraints.gatekeeper.sh/v1beta1/*    (dynamic — all constraint types)
kyverno.io/v1/clusterpolicies
kyverno.io/v1/policies
security.istio.io/v1/peerauthentications
security.istio.io/v1/authorizationpolicies
networking.istio.io/v1/sidecars
v1/resourcequotas
v1/limitranges
admissionregistration.k8s.io/v1/validatingwebhookconfigurations
admissionregistration.k8s.io/v1/mutatingwebhookconfigurations
```

### 2. Adapter Registry

Each constraint type is parsed by a pluggable adapter that converts raw unstructured objects into normalized `Constraint` models.

**Adapter interface:**
```go
type Adapter interface {
    // Name returns a unique identifier for this adapter.
    Name() string

    // Handles returns the GVRs this adapter can parse.
    Handles() []schema.GroupVersionResource

    // Parse converts an unstructured object into normalized constraints.
    // Returns multiple constraints because a single policy object can
    // contain multiple rules (e.g., a Kyverno ClusterPolicy with N rules).
    Parse(ctx context.Context, obj *unstructured.Unstructured) ([]Constraint, error)
}
```

**Built-in adapters** (ordered by implementation priority):

| Adapter | Target | Phase |
|---|---|---|
| `networkpolicy` | `NetworkPolicy` | 1 |
| `resourcequota` | `ResourceQuota`, `LimitRange` | 1 |
| `webhook` | `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration` | 1 |
| `cilium` | `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy` | 2 |
| `gatekeeper` | `Constraint` (all types under `constraints.gatekeeper.sh`) | 3 |
| `kyverno` | `ClusterPolicy`, `Policy` | 3 |
| `istio` | `PeerAuthentication`, `AuthorizationPolicy`, `Sidecar` | 4 |
| `generic` | Fallback for unknown CRDs — extracts selectors and metadata | 1 |

**Custom adapters**: Platform teams can register custom adapters via `ConstraintProfile` CRDs, or compile and link their own adapters into a custom controller build.

### 3. Constraint Indexer

The indexer maintains an in-memory, queryable index of all normalized constraints. It supports queries like:

- "All constraints affecting namespace X"
- "All constraints matching workload labels {app: foo, tier: backend}"
- "All network-type constraints restricting egress"
- "All constraints from source GVR cilium.io/v2/ciliumnetworkpolicies"

The index is updated reactively via informer callbacks (add/update/delete). It does not poll.

**Normalized Constraint model:**
```go
type Constraint struct {
    // Identity
    UID        types.UID
    Source     schema.GroupVersionResource
    Name       string
    Namespace  string // empty = cluster-scoped

    // Scope
    AffectedNamespaces []string         // which namespaces this applies to
    NamespaceSelector  *metav1.LabelSelector
    WorkloadSelector   *metav1.LabelSelector // which workloads within those namespaces
    ResourceTargets    []ResourceTarget // which resource types (for admission constraints)

    // Effect
    ConstraintType     ConstraintType   // NetworkEgress, NetworkIngress, Admission, ResourceLimit, etc.
    Effect             string           // deny, restrict, warn, audit
    Severity           Severity         // Critical, Warning, Info

    // Details (adapter-specific, used for full-detail notifications)
    Details            map[string]interface{}

    // Human-readable
    Summary            string  // "Restricts egress to ports 443, 8443 for pods matching tier=frontend"
    RemediationHint    string  // "Contact platform-team@company.com to request an exception"

    // Reference back to source object
    RawObject          *unstructured.Unstructured
}
```

### 4. Correlation Engine

The correlation engine connects observed failures to indexed constraints. It has three input streams:

**a) Kubernetes Events (reactive)**
Watches all Warning events cluster-wide. Filters for reasons indicating policy blocks: `FailedCreate`, `FailedScheduling`, `FailedValidation`, etc. Extracts the error message, identifies the affected workload, queries the constraint index for matching constraints, and enriches the notification.

**b) Hubble Flow Drops (real-time, optional)**
If Hubble Relay is available, subscribes to the flow stream filtered for `verdict=DROPPED`. Each dropped flow includes source/destination pod identity, port, protocol, and the policy that caused the drop. This is the highest-fidelity signal — it gives exact "policy X dropped traffic from pod A to pod B on port C" data.

**c) Admission Dry-Run (proactive, optional)**
For newly created workloads, the admission webhook can run dry-run checks against known constraint types and return warnings without blocking the request.

### 5. Requirement Evaluator

Detects *missing* resources that a workload likely needs. Uses two approaches:

**a) Inference rules** — hardcoded domain knowledge:
```
IF workload has annotation sidecar.istio.io/status
    AND no VirtualService or DestinationRule references it
THEN warn "No Istio routing configured for this workload"

IF workload has port named "http-metrics" or "metrics"
    AND no ServiceMonitor/PodMonitor targets its labels
THEN warn "No Prometheus ServiceMonitor targets this workload"

IF namespace has label istio-injection=enabled
    AND no PeerAuthentication exists in namespace
THEN warn "No mTLS policy configured; using mesh-wide defaults"
```

**b) Annotation-driven requirements** — workload authors declare what they need:
```yaml
annotations:
  potoo.io/requires: |
    - gvr: monitoring.coreos.com/v1/servicemonitors
      matching: app=my-service
      reason: "Prometheus won't scrape without a ServiceMonitor"
```

**Debouncing**: Missing-resource alerts are debounced (default 60-120 seconds) to avoid false positives during GitOps sync cycles where resources arrive in unpredictable order.

### 6. Notification Dispatcher

Delivers notifications through multiple channels with privacy-aware detail levels.

**Channels:**
- **Kubernetes Events**: Attached to the affected workload. Visible via `kubectl describe`. Always enabled.
- **ConstraintReport CRD**: Per-namespace summary of all constraints affecting that namespace. Updated continuously.
- **Slack/Teams webhooks**: Optional. For critical-severity constraints (traffic drops, admission blocks).
- **External webhook**: Generic HTTP POST for integration with custom systems.

**Privacy scoping**: See [PRIVACY_MODEL.md](PRIVACY_MODEL.md). Each notification is rendered at the appropriate detail level for the recipient.

**Rate limiting**: Circuit breaker at 100 events/minute per namespace. Prevents notification storms during mass policy changes.

## Data Flow

```
CRD Install/Update ──► Discovery Engine ──► Adapter ──► Constraint Indexer
                                                              │
Workload Deploy ──► Admission Webhook ──► Warning ◄──────────┤
                                                              │
K8s Warning Event ──► Correlation Engine ──► Match ◄──────────┤
                                                              │
Hubble Flow Drop ──► Correlation Engine ──► Match ◄──────────┘
                                                    │
                                                    ▼
                                          Notification Dispatcher
                                           │        │         │
                                     K8s Event  CRD Report  Slack
```

## Failure Modes and Graceful Degradation

| Failure | Impact | Mitigation |
|---|---|---|
| Controller crash | No new notifications until failover | 2-replica leader election; standby has warm caches |
| Webhook crash | No deploy-time warnings | `failurePolicy: Ignore` — deploys proceed normally |
| Hubble Relay unreachable | No real-time flow drop detection | Controller continues with K8s API data only; metric exposed |
| Adapter parse error | Single constraint type unreadable | Isolated per-adapter; other adapters unaffected; logged + metriced |
| etcd overload from Events | Notification storm | Circuit breaker at 100 events/min/namespace |
| Unknown CRD schema change | Adapter returns parse errors | Generic adapter fallback; admin alerted via metrics |

## Metrics

Exposed on `/metrics` (Prometheus format):

```
potoo_constraints_total{type, severity, adapter}
potoo_notifications_total{scope, channel, severity, namespace}
potoo_discovery_duration_seconds{}
potoo_adapter_errors_total{adapter}
potoo_watched_resources_total{}
potoo_hubble_flow_drops_total{namespace}
potoo_requirement_violations_total{rule, namespace}
potoo_notification_rate_limited_total{namespace}
```
