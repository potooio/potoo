# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- NotificationPolicy routing in dispatcher — watch NotificationPolicy CRDs and route constraint notifications to configured webhook channels based on severity thresholds and detail-level scoping; PolicyRouter with thread-safe sender lifecycle management (diff-based create/stop), auth token resolution from K8s Secrets, CLI-flag webhook preserved as static fallback
- Generic webhook POST sender for constraint notifications — async worker pool with bounded channel, linear backoff retry (1s, 2s) on transient 5xx/connection errors, bearer token auth via K8s Secret, TLS skip-verify option, severity-based filtering, Prometheus metrics (`potoo_webhook_send_total`, `potoo_webhook_send_duration_seconds`)
- `Sender` interface for extensible notification channels (webhook, future Slack/Teams)
- WebhookConfig CRD fields: `timeoutSeconds`, `insecureSkipVerify`, `minSeverity`, `authSecretRef`
- Controller CLI flags: `--webhook-url`, `--webhook-timeout`, `--webhook-insecure-skip-verify`, `--webhook-min-severity`
- Helm chart webhook configuration: `notifications.webhook.timeoutSeconds`, `insecureSkipVerify`, `minSeverity`
- E2E test for webhook notification pipeline — deploys nginx-based receiver, patches controller, verifies end-to-end delivery
- E2E tests for Cilium adapter and Hubble flow drop detection — CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy discovery, L7 policy detection, deny-all policy, ingressDeny rules, egress policy, Hubble flow drop correlation, graceful degradation, deletion lifecycle, ConstraintReport integration
- E2E test tier separation — Tier 1 (CRDs-only, default `make test-e2e`), Tier 2 (`make test-e2e-cilium` with Kind+Cilium CNI+Hubble), Tier 3 (`make test-e2e-istio` placeholder); robust `hack/e2e-teardown.sh` with finalizer cleanup, CRD instance removal, and Kind cluster deletion verification
- Istio adapter — parses AuthorizationPolicy (`security.istio.io/v1`), PeerAuthentication (`security.istio.io/v1`), and Sidecar (`networking.istio.io/v1`) into MeshPolicy constraints with severity mapping (DENY→Critical, STRICT→Warning, Sidecar→Info)
- Register Cilium adapter in controller (pre-existing adapter was implemented but not wired)
- Add Gatekeeper, Kyverno, Cilium, and Istio to capabilities API `DefaultAdapters()` for accurate adapter reporting
- E2E tests for Istio adapter — AuthorizationPolicy discovery, PeerAuthentication mTLS mode detection, Sidecar egress restriction, deletion lifecycle, ConstraintReport integration
- E2E setup/teardown now installs and removes Istio CRDs (CRDs-only, no control plane required)
- E2E tests for generic adapter framework and ConstraintProfile controller — profile CRUD lifecycle, field path extraction, annotation-based auto-detection, heuristic boundary, ConstraintReport generation, enabled/disabled toggle, negative tests (invalid field paths, missing target CRD, malformed spec)
- E2E tests for MCP server constraint queries — capabilities, health, tool/resource listing, constraint query with type and label filters, privacy scoping (name redaction at Summary level), empty-index behavior, error explanation matching
- Helm chart: conditional MCP port exposure (`mcp.enabled`) in controller Deployment and Service
- E2E setup enables MCP server (`--set mcp.enabled=true`) for MCP endpoint testing
- Annotation-based requirement rule (`annotation-requirements`) — workloads declare custom companion resource checks via `potoo.io/requires` annotation with YAML list of `{gvr, matching, reason}` entries; supports arbitrary GVR lookup, label-selector filtering, and custom reasons
- CRD-installed detection rule (`crd-installed`) — alerts when workloads reference functionality from CRDs that are not installed (ServiceMonitor, PeerAuthentication, ClusterIssuer)
- Controller tuning flag `--requirement-debounce` (with matching Helm value `requirements.debounceSeconds`) for configuring missing-resource alert debounce duration
- E2E tests for missing resource detection — ServiceMonitor/PodMonitor alerts, Istio mTLS, cert-manager issuer, CRD existence detection, debounce correctness (no false positives on delete+recreate)
- E2E setup now installs Prometheus Operator CRDs (ServiceMonitor, PodMonitor) for requirements testing
- Controller tuning flags: `--annotator-debounce`, `--annotator-cache-ttl`, `--report-debounce`, `--report-workers` (with matching Helm values) for fine-grained control of workload annotation and ConstraintReport reconciliation timing
- ConstraintReport worker pool for concurrent per-namespace reconciliation
- E2E suite parallelization with namespace isolation — test groups run concurrently via `t.Parallel()`, reducing wall-clock time on multi-core runners
- E2E tests for Kyverno adapter — ClusterPolicy and Policy discovery, Enforce/Audit severity mapping, multi-rule parsing, match clause parsing (any/all), mutate/generate Info severity, deletion lifecycle
- E2E setup/teardown (`e2e-setup`, `e2e-setup-dd`) now installs and removes Kyverno as a test dependency
- E2E tests for Gatekeeper adapter — constraint discovery, enforcement action mapping, match block parsing, multi-template dynamic discovery, constraint deletion lifecycle
- E2E setup/teardown (`e2e-setup`, `e2e-setup-dd`) now installs and removes Gatekeeper as a test dependency
- E2E tests for admission webhook warnings — deployment readiness, constraint warning capture, fail-open behavior, self-signed TLS certificate injection, PDB enforcement
- Wire controller constraint query API (`GET /api/v1/constraints`) for webhook integration
- E2E tests for correlation engine and Event notifications — event creation with structured annotations, deduplication, privacy scoping, workload annotation patching, rate limiting
- Wire EventBuilder into Dispatcher for structured annotations on all emitted Events
- E2E tests for core discovery engine and native K8s adapters (NetworkPolicy, ResourceQuota, LimitRange, WebhookConfiguration, generic CRD, periodic rescan)
- E2E tests for constraint indexer and ConstraintReport reconciliation — CRUD lifecycle, severity counting, machine-readable validation, cluster-scoped constraint propagation
- E2E test infrastructure and harness for Kind cluster testing — shared helpers, testify suite, Makefile targets (`e2e-setup`, `e2e`, `e2e-teardown`)
- Hubble flow drop streaming — connects to Hubble Relay and streams `verdict=DROPPED` flows for real-time network policy correlation
- Generic adapter field-path configuration — ConstraintProfile `fieldPaths` enables custom extraction of selectors, namespace selectors, effects, and summaries from arbitrary CRD schemas
- ConstraintProfile controller — controller-runtime reconciler for immediate profile registration/unregistration (no rescan delay)
- CRD annotation discovery — CRDs annotated with `potoo.io/is-policy: "true"` are automatically treated as constraint sources
- Discovery tuning — configurable `additionalPolicyGroups`, `additionalPolicyNameHints`, and `checkCRDAnnotations` flags for heuristic customization
- Dynamic adapter registry — `Unregister`, `RegisterGVR`, and `UnregisterGVR` methods for runtime profile-driven adapter management
- Example ConstraintProfiles for cert-manager, Crossplane, and Argo Rollouts

### Fixed

- Requirements evaluator: fix debounce cleanup evicting actively-detected missing resources — `CleanupStaleEntries` now tracks `lastSeen` per entry and only evicts entries not seen for 2x the debounce duration, preventing constraint flickering in ConstraintReports
- E2E: fix IstioMTLSMissing test matchFn using case-sensitive string match on reason field — now matches on structured `expectedKind` field
- Webhook: fix self-signed certificate injection race — `UpdateWebhookCABundle` now returns an error when the VWC does not exist (enabling retry), startup retries with exponential backoff, and the rotation watcher syncs caBundle on first tick as a safety net
- Dispatcher: fix burst=0 rate limiter floor when RateLimitPerMinute < 10 (allows at least 1 burst event)
- Correlator: fix TOCTOU race in deduplication by replacing isDuplicate+markSeen with atomic tryMarkSeen
- Dispatcher: add periodic eviction of stale namespace rate limiters to prevent unbounded map growth
- Hubble client: fix data race on connection field during shutdown
- Hubble client: use signal-handler context instead of background context for lifecycle management
- Hubble client: fix incorrect drop reason mappings and replace magic integers with proto enum constants
- Hubble client: add explicit ICMPv6 flow handling
- Hubble client: move DropReason.String() to production code
- Hubble client: fix reconnect counter to increment on stream disconnect, not after backoff timer
- Hubble client: deep-copy label maps and workload slices in FlowDropBuilder.Build()
- Docs: standardize GitHub org references to `potooio/potoo` across all documentation (CONTRIBUTING.md, SECURITY.md, docs site config, installation guides)
- Docs: fix MCP `for_workload` format in response examples — now correctly shows `namespace/Kind/name` format matching actual handler output
- Docs: add missing `metrics` field reference to MCP query response documentation
- Docs: update PROJECT_PLAN.md Phase 4 checkboxes to reflect completed Istio adapter and annotation-based requirements

### Documentation

- HTTP API reference (`docs/controller/http-api.md`) — documents `GET /api/v1/capabilities`, `/api/v1/constraints`, `/api/v1/health`, `/health` with request/response examples
- JSON naming convention section in AGENT_OUTPUTS.md — explains intentional camelCase (CRDs/HTTP API) vs snake_case (MCP/CLI) split
- Troubleshooting guide (`docs/troubleshooting.md`) — covers constraints not discovered, events not appearing, webhook issues, Hubble connection failures, MCP server unreachable
- Expanded webhook documentation — cert-manager vs self-signed tradeoff comparison, issuerRef vs issuerName precedence, cert-manager configuration examples
- Advanced ConstraintProfile field-path examples — Crossplane XRD, cert-manager Certificate, nested array selectors with CRD patterns
- NotificationPolicy routing examples — severity-based routing, multi-channel setup, privacy-strict policy
- Helm chart discovery section examples with detailed comments, cert-manager issuer configuration

## [0.1.0] - 2026-02-10

### Added

- Core controller with leader election and CRD rescan
- Discovery engine with automatic CRD scanning and heuristic detection
- Constraint adapters: NetworkPolicy, ResourceQuota, LimitRange, WebhookConfiguration, Cilium, Gatekeeper, Kyverno, Generic
- Adapter auto-detection (`auto` mode enables adapters when CRDs are present)
- In-memory constraint indexer with namespace/label/type queries
- Event correlator for matching Kubernetes events to constraints
- Missing resource detection (ServiceMonitor, VirtualService, PeerAuthentication) with configurable debounce
- Admission webhook (fail-open, warning mode) as separate deployment
- ConstraintReport CRD with human-readable and machine-readable sections
- ConstraintProfile CRD for custom CRD registration and adapter tuning
- NotificationPolicy CRD for privacy-scoped notification configuration
- Notification dispatcher: Kubernetes Events, ConstraintReports, Slack, generic webhooks
- Notification deduplication and rate limiting
- Privacy model with developer/platform-admin scoping and detail levels
- Workload annotation with constraint summaries
- MCP server for AI agent integration (SSE and stdio transports)
- HTTP API server (`/api/v1/health`, `/api/v1/capabilities`, `/openapi/v3`)
- CLI (`potoo query`, `potoo explain`, `potoo check`, `potoo status`)
- kubectl plugin (`kubectl sentinel`)
- Optional Hubble gRPC integration for real-time flow drop detection
- Prometheus metrics and optional ServiceMonitor/Grafana dashboard
- Helm chart with comprehensive values.yaml
- Documentation: architecture, quickstart, configuration reference, adapter guide, privacy model, CRD reference

[Unreleased]: https://github.com/potooio/potoo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/potooio/potoo/releases/tag/v0.1.0
