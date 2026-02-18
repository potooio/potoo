# Project Plan

## Overview

Potoo is delivered in 7 phases. Each phase is independently useful — Phase 1 alone delivers real value.

## Phase 0: Scaffolding (Weeks 1-3)

**Goal**: Project structure, CI pipeline, CRD schemas, RBAC, Helm chart skeleton.

### Deliverables
- [x] Go module with `controller-runtime` skeleton
- [x] CRD type definitions (`ConstraintProfile`, `NotificationPolicy`, `ConstraintReport`)
- [x] CRD manifests generated via `controller-gen`
- [x] RBAC ClusterRole and ServiceAccount
- [x] Helm chart with configurable values
- [x] Dockerfile (distroless base)
- [x] CI pipeline (GitHub Actions): lint, test, build, image push
- [x] Makefile with standard targets (`make build`, `make test`, `make manifests`, `make docker-build`)
- [x] Adapter interface definition
- [x] Core type definitions (`Constraint`, `ConstraintType`, `Severity`, etc.)
- [x] Leader election setup
- [x] Health/readiness probes (`/healthz`, `/readyz`)
- [x] Metrics endpoint (`/metrics`)

### Key Decisions to Lock In
- CRD API version: `v1alpha1`
- Controller namespace: `potoo-system`
- Helm chart name: `potoo`
- Go module path: `github.com/potooio/potoo`
- License: Apache 2.0

### Exit Criteria
- `make build` produces a working binary
- `make test` passes with >0 tests
- Helm chart installs on a Kind cluster without errors
- CRDs register successfully
- Controller starts, elects leader, serves `/healthz` and `/metrics`

---

## Phase 1: Core Discovery + Native K8s Adapters (Weeks 4-9)

**Goal**: Discover and index native Kubernetes constraint resources. Emit notifications.

### Deliverables
- [x] Discovery engine: scan `discovery.ServerPreferredResources()`, match against known GVRs + heuristics
- [x] Dynamic informer management: spin up/down informers for discovered GVRs
- [x] Periodic re-scan (every 5 min) for newly installed CRDs
- [x] **Adapter: NetworkPolicy** — parse `podSelector`, `ingress`, `egress`, `policyTypes`
- [x] **Adapter: ResourceQuota** — parse hard limits, current usage
- [x] **Adapter: LimitRange** — parse default/min/max for containers
- [x] **Adapter: ValidatingWebhookConfiguration** — parse `rules`, `namespaceSelector`, `failurePolicy`
- [x] **Adapter: MutatingWebhookConfiguration** — same as above
- [x] **Adapter: Generic** — fallback for unknown CRDs; extract `metadata`, any `selector` fields
- [x] Constraint indexer: in-memory index with namespace/label/type queries
- [x] Correlation engine: watch Warning events, match to indexed constraints
- [x] Notification via Kubernetes Events on affected workloads
- [x] `ConstraintReport` CRD: per-namespace summary, updated on constraint changes
- [x] Privacy scoping: developer vs. admin detail levels
- [x] Unit tests for all adapters (fixture YAML → expected `Constraint` output)
- [x] Integration tests with `envtest`

### Testing Strategy
- Unit: adapter parse tests with fixture YAML files (20+ fixtures per adapter)
- Integration: `envtest` with real API server — test discovery, informer setup, Event creation
- Manual: Kind cluster with sample NetworkPolicies and ResourceQuotas

### Exit Criteria
- `kubectl get constraintreports -n <namespace>` shows accurate constraint summary
- Creating a NetworkPolicy triggers an Event on affected workloads
- ResourceQuota usage warnings appear when usage > 75%
- Unknown CRDs are detected and reported with generic metadata

---

## Phase 2: Cilium Adapter + Hubble Integration (Weeks 10-13)

**Goal**: Deep Cilium policy parsing and real-time traffic drop detection.

### Deliverables
- [x] **Adapter: CiliumNetworkPolicy** — parse `endpointSelector`, `ingress`/`egress` rules, L3/L4/L7 policies, `toPorts`, `toCIDR`, `toEntities`, `toServices`, `toFQDNs`
- [x] **Adapter: CiliumClusterwideNetworkPolicy** — same, cluster-scoped
- [x] Hubble client: connect to Hubble Relay gRPC API
- [x] Flow stream subscription: filter for `verdict=DROPPED`
- [x] Flow-to-constraint correlation: match dropped flows to CiliumNetworkPolicy rules
- [x] Service map: maintain mapping of `service name → port` using Service/Endpoint objects
- [x] Semantic notifications: "Access to prometheus-server.monitoring:9090 blocked" not just "port 9090 blocked"
- [x] Hubble graceful degradation: continue without Hubble if Relay is unreachable
- [x] Helm values: `hubble.enabled`, `hubble.relayAddress`

### Testing Strategy
- Unit: Cilium policy YAML fixtures → expected constraints
- Integration: Kind + Cilium (cilium/cilium Helm chart) — deploy policies, verify constraint indexing
- E2E: Deploy workload, apply restrictive policy, verify notification appears within 60 seconds

### Exit Criteria
- CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy are auto-discovered and indexed
- When Hubble is available, traffic drops generate developer-visible Events within 30 seconds
- When Hubble is unavailable, the controller continues operating with degraded functionality logged

---

## Phase 3: Gatekeeper + Kyverno Adapters + Admission Webhook (Weeks 14-17)

**Goal**: Support the two major policy engines and add deploy-time warnings.

### Deliverables
- [x] **Adapter: Gatekeeper Constraints** — discover all CRDs under `constraints.gatekeeper.sh`, parse `match` blocks (kinds, namespaces, labelSelector), extract `parameters` and `rego` for human-readable summaries
- [x] **Adapter: Kyverno ClusterPolicy/Policy** — parse `match`/`exclude`, `validate`/`mutate`/`generate` rules
- [x] Admission webhook deployment (separate Deployment, 2+ replicas)
- [x] Warning-mode webhook: return admission warnings (not rejections) for workloads matching known constraints
- [x] `failurePolicy: Ignore` — always fail-open
- [x] PodDisruptionBudget for webhook pods
- [x] Anti-affinity for webhook pod scheduling
- [x] Webhook certificate management (cert-manager or self-signed rotation)
- [x] Helm values: `admissionWebhook.enabled`, `admissionWebhook.replicas`, `admissionWebhook.failurePolicy`

### Testing Strategy
- Unit: Gatekeeper constraint template + constraint fixtures → expected constraints
- Unit: Kyverno policy fixtures → expected constraints
- Integration: envtest with Gatekeeper/Kyverno CRDs installed
- E2E: Kind + Gatekeeper — create constraint, deploy violating resource, verify warning

### Exit Criteria
- All Gatekeeper constraint types are auto-discovered (dynamic, not hardcoded)
- Kyverno policies in both Enforce and Audit mode are indexed
- `kubectl apply` shows admission warnings for workloads matching constraints
- Webhook failure does not block any deployments

---

## Phase 4: Istio/Linkerd + Missing Resource Detection (Weeks 18-23)

**Goal**: Service mesh awareness and proactive missing-resource alerts.

### Deliverables
- [x] **Adapter: Istio PeerAuthentication** — parse mTLS mode, selector, namespace scope
- [x] **Adapter: Istio AuthorizationPolicy** — parse source/operation rules
- [x] **Adapter: Istio Sidecar** — parse egress/ingress listeners, workloadSelector
- [x] Requirement evaluator engine with rule interface
- [x] Built-in requirement rules:
  - Istio sidecar present → VirtualService/DestinationRule should exist
  - Port named "metrics"/"http-metrics" → ServiceMonitor/PodMonitor should exist
  - Namespace with istio-injection=enabled → PeerAuthentication should exist
  - cert-manager Certificate referenced → ClusterIssuer/Issuer should exist
- [x] Annotation-based requirements (`potoo.io/requires`)
- [x] Debounce logic for missing-resource notifications (configurable, default 120s)
- [x] Detection of missing CRDs themselves ("Your manifest requires CRD X which isn't installed")
- [ ] ArgoCD Application / Flux Kustomization health status monitoring (parse "no matches for kind" errors)
- [x] Helm values: `requirements.enabled`, `requirements.debounceSeconds`

### Testing Strategy
- Unit: requirement rule fixtures (workload YAML + cluster state → expected requirements)
- Integration: envtest with Istio CRDs
- E2E: Kind + Istio — deploy workload with sidecar, verify missing VirtualService warning

### Exit Criteria
- Istio auth policies are discovered and indexed
- Missing ServiceMonitor warning appears within 2 minutes of deploying a workload with metrics port
- Debouncing suppresses false positives during ArgoCD sync cycles
- Annotation-based requirements work for custom needs

---

## Phase 5: External Notifications + Dashboard (Weeks 24-27)

**Goal**: Deliver notifications outside of kubectl and provide visual overview.

### Deliverables
- [ ] Slack integration: webhook-based, configurable per severity and namespace
- [ ] Microsoft Teams integration: similar to Slack
- [x] Generic webhook: HTTP POST with JSON payload for custom integrations
- [x] Notification deduplication: track notification state, only re-notify on change
- [x] Notification routing: map namespaces to notification channels via `NotificationPolicy` CRD
- [ ] Grafana dashboard JSON (shipped with Helm chart)
- [ ] Prometheus alerting rules (shipped with Helm chart)
- [ ] Optional web UI: lightweight read-only dashboard showing per-namespace constraint reports
- [ ] Helm values: `notifications.slack.enabled`, `notifications.webhookUrl`, etc.

### Testing Strategy
- Unit: notification rendering tests (constraint → expected message per scope)
- Integration: mock webhook server for Slack/Teams payload verification
- Manual: end-to-end Slack notification test in staging cluster

### Exit Criteria
- Slack notifications fire for critical-severity constraints within 60 seconds
- Notifications deduplicate (same constraint doesn't re-notify unless changed)
- Grafana dashboard shows constraint count, notification rate, adapter health

---

## Phase 6: Generic Adapter Framework + ConstraintProfile CRD (Weeks 28-31)

**Goal**: Enable platform teams to register and configure arbitrary constraint types.

### Deliverables
- [x] `ConstraintProfile` CRD controller: watch for ConstraintProfile resources, configure adapters dynamically
- [x] Generic adapter configuration: field path expressions for extracting selectors, namespaces, effects from arbitrary CRDs
- [x] `potoo.io/is-policy: "true"` annotation support on CRDs
- [x] Auto-detection tuning: configurable heuristic thresholds
- [x] Documentation: how to write a custom adapter (Go plugin or ConstraintProfile)
- [x] Example adapters: cert-manager, Crossplane, Argo Rollouts

### Exit Criteria
- Platform admin can register a custom CRD as a constraint type without recompiling
- ConstraintProfile updates take effect within 30 seconds
- Documentation enables a Go developer to write a new adapter in < 2 hours

---

## Timeline Summary

| Phase | Duration | Cumulative |
|---|---|---|
| 0: Scaffolding | 3 weeks | Week 3 |
| 1: Core + Native Adapters | 6 weeks | Week 9 |
| 2: Cilium + Hubble | 4 weeks | Week 13 |
| 3: Gatekeeper + Kyverno + Webhook | 4 weeks | Week 17 |
| 4: Istio + Missing Resources | 6 weeks | Week 23 |
| 5: External Notifications + Dashboard | 4 weeks | Week 27 |
| 6: Generic Framework | 4 weeks | Week 31 |

**Total open source core**: ~31 weeks (~8 months) for a 1-2 person team.
**Minimum viable release**: Phase 1 (Week 9) — native K8s constraints with Event notifications.
