# CLAUDE.md

## What This Is
Kubernetes operator. Discovers ALL constraints/policies/quotas in a cluster across all policy engines (Cilium, Gatekeeper, Kyverno, Istio, native K8s, webhooks, arbitrary CRDs). Notifies developers when constraints block their workloads. Not a policy engine — a policy *explainer*.

## Workflow
1. Read `TASKS.md` for the structured task queue. Tasks have IDs, deps, verify commands, specs.
2. Work through tasks in order. Each task has a `verify:` command — run it.
3. Pre-written tests exist for most components. Remove `t.Skip()`, implement the code, make tests pass.
4. `grep -rn "IMPLEMENT:" internal/` finds all code stubs needing implementation.

## Commands
```
make build      # Must exit 0
make test       # Must exit 0
make lint       # Must exit 0 (runs golangci-lint v2 with .golangci.yml)
make manifests  # Generates CRD YAML into config/crd/
make generate   # Generates DeepCopy into api/v1alpha1/zz_generated.deepcopy.go
make run        # Run locally against current kubeconfig (no leader election)
```

## Pre-Commit Checks (run before every commit)
```
gofmt -l .              # Must produce no output
golangci-lint run ./... # Must produce 0 issues
go test -race ./...     # Must exit 0
```
CI rejects commits that fail any of these. Fix lint issues before committing, not after.

## Rules (violating any of these is always wrong)
- Parse external CRDs from `unstructured.Unstructured` only. Never import typed policy engine clients.
- Admission webhook failurePolicy is always `Ignore`. Never `Fail`.
- Developer notifications never contain cross-namespace policy details (see docs/PRIVACY_MODEL.md).
- Always nil-check unstructured field access. CRD schemas change between versions.
- Debounce missing-resource alerts 120s default.
- `*/* get,list,watch` RBAC is intentional.
- Adapters must be goroutine-safe and never mutate input objects.

## Package Map
```
api/v1alpha1/          CRD types (ConstraintReport w/ MachineReadable, ConstraintProfile, NotificationPolicy)
internal/types/        Constraint model, Adapter interface, RemediationStep, RequirementRule
internal/util/         Safe unstructured field helpers — use these everywhere
internal/adapters/     Registry + one sub-package per policy engine
internal/annotations/  Structured annotation key constants for Events and workloads
internal/controller/   ConstraintProfile reconciler (controller-runtime)
internal/discovery/    CRD scanner, dynamic informer lifecycle, profile registration
internal/indexer/      In-memory constraint store, query by namespace/labels/type
internal/correlator/   K8s event watcher → constraint matcher
internal/notifier/     Notification rendering + dispatch + workload annotator + report reconciler
internal/mcp/          MCP server — AI agents query constraints, explain errors, pre-check deploys
internal/api/          HTTP API (/capabilities, /health) for agent discovery
internal/requirements/ Missing-resource detection (ServiceMonitor, VirtualService, etc.)
internal/hubble/       Optional Hubble gRPC client for flow drop detection
cmd/controller/        Main entrypoint, wires everything
cmd/webhook/           Admission webhook binary (separate deployment)
cmd/potooctl/potoo-sentinel/  kubectl plugin — structured JSON output matching MCP schemas
```

## Adapter Pattern (copy this exactly for every new adapter)
```go
// internal/adapters/<name>/adapter.go
type Adapter struct{}
func New() *Adapter { return &Adapter{} }
func (a *Adapter) Name() string { return "<name>" }
func (a *Adapter) Handles() []schema.GroupVersionResource { return []schema.GroupVersionResource{...} }
func (a *Adapter) Parse(ctx context.Context, obj *unstructured.Unstructured) ([]types.Constraint, error) { ... }
```
Reference implementation: `internal/adapters/networkpolicy/`
