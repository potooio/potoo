---
layout: default
title: E2E Testing
parent: Contributing
nav_order: 1
---

# E2E Testing
{: .no_toc }

Run end-to-end tests against a real Kubernetes cluster.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

E2E tests validate Potoo's full lifecycle against a real cluster: constraint
discovery, event emission, workload annotation, and controller health. They run
separately from unit and integration tests via the `//go:build e2e` tag.

### Test Tiers

E2E tests are organized into tiers based on infrastructure requirements:

| Tier | Target | Requirements | What It Tests |
|---|---|---|---|
| **1** (default) | `make test-e2e` | CRDs only, ~3GB RAM | Core discovery, native adapters, Gatekeeper, Kyverno, Istio CRDs, generic adapter, correlation, webhook, MCP, missing resources |
| **2** (Cilium) | `make test-e2e-cilium` | Cilium CNI + Hubble, ~4GB RAM | CiliumNetworkPolicy, Hubble flow drops, L7 policy, graceful degradation |
| **3** (Istio) | `make test-e2e-istio` | istiod running, ~5GB RAM | *Placeholder — not yet implemented* |

Tier 1 runs on every developer machine. Adapters that need external
infrastructure are skipped gracefully via `requireXXXInstalled()` helpers.
Tier 2 requires a dedicated Kind cluster with Cilium as the CNI.
Tier 3 is reserved for future Istio control plane tests.

{: .note }
**CI integration:** Tier 1 on every PR and Tier 2/3 on schedule or label
trigger are planned for a future workflow update. Currently, CI only runs
unit tests.

### Cluster Backends

| Backend | Isolation | Extra Install | Use Case |
|---|---|---|---|
| **Docker Desktop K8s** | Shared cluster | None | Quick iteration, WSL2 friendly |
| **Kind** | Disposable cluster | `kind` CLI | CI, clean-room testing |
| **Kind (Cilium)** | Disposable, custom CNI | `kind` + `helm` | Tier 2 Cilium E2E |

---

## Docker Desktop (Recommended for Local Dev)

Docker Desktop's built-in Kubernetes shares the local Docker daemon, so
locally-built images are available without any image-loading step.

### Prerequisites

- Docker Desktop with **Kubernetes enabled** (Settings > Kubernetes > Enable)
- `kubectl`, `helm`, Go 1.25+

### Workflow

```bash
# Verify your cluster is running
kubectl cluster-info

# Build images, install CRDs, deploy controller
make e2e-setup-dd

# Run the tests
make e2e

# Clean up (removes only Potoo resources)
make e2e-teardown-dd
```

{: .note }
`e2e-teardown-dd` only removes Potoo's Helm release, CRDs, and
test namespaces. Your other workloads are not affected.

### What Happens

1. **`make e2e-setup-dd`** builds controller and webhook Docker images, applies
   CRDs, and deploys the controller via Helm with simplified settings (1 replica,
   no leader election, webhook enabled, `pullPolicy=Never`).
2. **`make e2e`** runs `go test ./test/e2e/... -v -tags=e2e -timeout 15m`. The
   test suite connects via your kubeconfig, creates labeled namespaces, verifies
   the controller is healthy, runs tests in parallel, and cleans up.
3. **`make e2e-teardown-dd`** runs `hack/e2e-teardown.sh --skip-cluster-delete`,
   which uninstalls Helm releases, cleans CRD instances, removes namespaces
   (with finalizer cleanup), and deletes CRDs. The cluster itself is preserved.

---

## Kind (Isolated Cluster)

Kind creates a full Kubernetes cluster inside Docker containers. Everything is
destroyed on teardown.

### Prerequisites

- Docker, `kubectl`, `helm`, Go 1.25+
- [Kind](https://kind.sigs.k8s.io/): `go install sigs.k8s.io/kind@latest`

{: .warning }
**WSL2 users:** Kind requires cgroup v2. If `cat /sys/fs/cgroup/cgroup.controllers`
fails, add `kernelCommandLine = cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1`
to `%USERPROFILE%\.wslconfig` and run `wsl --shutdown`. Or use Docker Desktop
Kubernetes instead.

### Workflow

```bash
# Build images, create Kind cluster, load images, deploy controller
make e2e-setup

# Run the tests
make e2e

# Tear down (deletes the entire Kind cluster)
make e2e-teardown
```

---

## Writing E2E Tests

E2E test files live in `test/e2e/` and must include the build tag:

```go
//go:build e2e
// +build e2e
```

### Test Suite

Tests use Go's standard `TestMain` entry point (not testify suites). Shared
Kubernetes clients are initialized once and stored in package-level variables:

| Variable | Type | Description |
|---|---|---|
| `sharedClientset` | `kubernetes.Interface` | Standard Kubernetes client |
| `sharedDynamicClient` | `dynamic.Interface` | For unstructured objects |

Each top-level test function creates its own namespace via
`createTestNamespace()` and uses `t.Parallel()` for concurrency:

```go
func TestMyFeature(t *testing.T) {
    t.Parallel()
    ns, cleanup := createTestNamespace(t, sharedClientset)
    t.Cleanup(cleanup)
    // Use sharedClientset, sharedDynamicClient, ns
}
```

### Available Helpers

All helpers are in `helpers_test.go`:

| Helper | Purpose |
|---|---|
| `waitForCondition(t, timeout, interval, fn)` | Generic polling loop |
| `waitForControllerReady(t, clientset, timeout)` | Wait for controller deployment |
| `waitForDeploymentReady(t, clientset, ns, name, timeout)` | Wait for any deployment |
| `createTestNamespace(t, clientset)` | Create labeled namespace + cleanup func |
| `deleteNamespace(t, clientset, name, timeout)` | Delete and wait for removal |
| `waitForEvent(t, clientset, ns, objectName, timeout)` | Poll for K8s Events on an object |
| `assertEventExists(t, clientset, ns, workload, annotations, timeout)` | Assert Potoo event with annotations |
| `assertEventAnnotation(t, event, key, value)` | Check single annotation |
| `assertManagedByPotoo(t, event)` | Check `potoo.io/managed-by` |
| `applyUnstructured(t, dynamicClient, obj)` | Create an unstructured object |
| `deleteUnstructured(t, dynamicClient, gvr, ns, name)` | Delete an unstructured object |
| `getControllerLogs(t, clientset, tailLines)` | Retrieve controller pod logs |
| `getConstraintReport(t, dynClient, ns, timeout)` | Poll for ConstraintReport "constraints" via dynamic client |
| `getReportStatus(report)` | Extract `.status` map from unstructured report (nil-safe) |
| `waitForReportCondition(t, dynClient, ns, timeout, condFn)` | Poll until condition is true on report status |
| `statusInt64(status, key)` | Safely extract int64 from status map field |
| `statusConstraintNames(status)` | Extract constraint names from `status.constraints[]` |
| `statusConstraintSources(status)` | Extract constraint sources from `status.constraints[]` |
| `createTestDeployment(t, dynamicClient, ns, name)` | Create a pause:3.9 Deployment + cleanup func |
| `waitForPotooEvent(t, clientset, ns, workload, timeout)` | Poll for ConstraintNotification Events from potoo-controller |
| `getPotooEvents(t, clientset, ns, workload)` | List Potoo events (non-waiting, for counting) |
| `createWarningEvent(t, clientset, ns, involved, kind)` | Create a synthetic Warning event for correlation testing |
| `waitForWorkloadAnnotation(t, dynClient, ns, deploy, key, timeout)` | Poll until a workload annotation is present |

### Example: Testing a NetworkPolicy Constraint

```go
func TestNetworkPolicyDiscovery(t *testing.T) {
    t.Parallel()
    ns, cleanup := createTestNamespace(t, sharedClientset)
    t.Cleanup(cleanup)

    // Create a NetworkPolicy in the test namespace
    np := &unstructured.Unstructured{
        Object: map[string]interface{}{
            "apiVersion": "networking.k8s.io/v1",
            "kind":       "NetworkPolicy",
            "metadata": map[string]interface{}{
                "name":      "deny-all-egress",
                "namespace": ns,
            },
            "spec": map[string]interface{}{
                "podSelector": map[string]interface{}{},
                "policyTypes": []interface{}{"Egress"},
            },
        },
    }
    applyUnstructured(t, sharedDynamicClient, np)

    // Wait for Potoo to discover and emit an event
    assertEventExists(t, sharedClientset, ns, "deny-all-egress",
        map[string]string{
            annotations.ManagedBy:           annotations.ManagedByValue,
            annotations.EventConstraintType: "NetworkEgress",
        },
        30*time.Second,
    )
}
```

### Constraint Report Tests

`constraint_report_test.go` verifies the indexer → report reconciler pipeline:

| Test | Verifies |
|---|---|
| `TestConstraintReportCreatedOnConstraint` | Creating a NetworkPolicy triggers a ConstraintReport with correct counts and machineReadable |
| `TestConstraintReportUpdateOnConstraintChange` | Updating a ResourceQuota re-reconciles the report (lastUpdated changes) |
| `TestConstraintReportDeleteConstraint` | Deleting a constraint removes it from the report (by name) |
| `TestConstraintReportMachineReadable` | machineReadable section has schemaVersion, detailLevel, structured entries with UID/SourceRef/Remediation |
| `TestConstraintReportSeverityCounts` | Multiple constraints produce correct severity counts (Warning + Info) |
| `TestConstraintReportClusterScopedConstraint` | Cluster-scoped webhook appears in the test namespace's report |

These tests use `waitForReportCondition` with timeouts of 60s (create) and 45s
(update) to account for the debounce + ticker + reconcile pipeline latency.

### Correlation & Notification Tests

`correlation_test.go` verifies the event correlation engine and notification pipeline:

| Test | Verifies |
|---|---|
| `TestCorrelationEventCreated` | Warning event → Correlator → Dispatcher → ConstraintNotification Event with structured annotations |
| `TestCorrelationDeduplication` | Same constraint-workload pair does not produce duplicate Events within the suppression window |
| `TestCorrelationPrivacyScoping` | Cross-namespace constraint Events use summary-level privacy (name redacted, no cross-NS details) |
| `TestWorkloadAnnotationPatched` | Deployment receives `potoo.io/status`, `potoo.io/constraints` JSON, severity counts |
| `TestCorrelationRateLimiting` | Burst Warning events are throttled by the per-namespace rate limiter |

These tests create a constraint first, wait for it to be indexed (via ConstraintReport),
then create synthetic Warning events to trigger the correlation pipeline. Timeouts
account for the full pipeline: informer sync + adapter parse + indexer upsert +
event watch + correlation + dispatch.

### Generic Adapter & ConstraintProfile Tests

`generic_adapter_test.go` verifies the Phase 6 generic adapter framework and ConstraintProfile controller:

| Test | Verifies |
|---|---|
| `TestGenericAdapter/ProfileLifecycle` | Creating a ConstraintProfile causes the generic adapter to watch a custom CRD, discover instances, and annotate workloads |
| `TestGenericAdapter/FieldPathExtraction` | Custom field paths (selectorPath, effectPath, summaryPath, namespaceSelectorPath) extract data from non-standard CRD fields |
| `TestGenericAdapter/ProfileUpdate` | Updating a ConstraintProfile (e.g., changing severity) propagates to parsed constraints within 60s |
| `TestGenericAdapter/ProfileDeletion` | Deleting a ConstraintProfile stops watching the target CRD and removes constraints from the index |
| `TestGenericAdapter/AnnotationAutoDetection` | CRDs annotated with `potoo.io/is-policy: "true"` are auto-discovered without a ConstraintProfile |
| `TestGenericAdapter/HeuristicBoundary` | CRDs outside default policy groups/hints are NOT auto-detected, but ARE detected after creating a ConstraintProfile |
| `TestGenericAdapter/ConstraintReport` | Constraints from the generic adapter appear in ConstraintReport with correct machine-readable data |
| `TestGenericAdapter/EnabledFalse` | A ConstraintProfile with `enabled: false` prevents the CRD from being watched |
| `TestGenericAdapter/NegativeTests/InvalidFieldPaths` | Invalid field paths produce graceful degradation (constraint still created, no crash) |
| `TestGenericAdapter/NegativeTests/MissingTargetCRD` | Profile pointing to non-existent GVR does not crash the controller |
| `TestGenericAdapter/NegativeTests/MalformedSpec` | Profile with empty GVR fields is handled gracefully |

Each subtest creates its own namespace and uses randomized CRD group names
(`e2e-<rand>.testing.io`) to avoid cross-test interference under `t.Parallel()`.

---

## Makefile Target Reference

### Tier 1 (Default)

| Target | Backend | Description |
|---|---|---|
| `make e2e-setup-dd` | Docker Desktop | Build images, install CRDs, deploy controller |
| `make e2e-teardown-dd` | Docker Desktop | Clean all state, preserve cluster |
| `make e2e-setup` | Kind | Create cluster, build/load images, deploy |
| `make e2e-teardown` | Kind | Delete Kind cluster and all resources |
| `make e2e` / `make test-e2e` | Any | Run Tier 1 E2E tests |

### Tier 2 (Cilium)

| Target | Backend | Description |
|---|---|---|
| `make e2e-setup-cilium` | Kind (Cilium) | Create Cilium Kind cluster, deploy everything |
| `make e2e-teardown-cilium` | Kind (Cilium) | Delete Cilium Kind cluster and all resources |
| `make test-e2e-cilium` | Kind (Cilium) | Run Tier 2 E2E tests |

### Tier 3 (Istio — Placeholder)

| Target | Backend | Description |
|---|---|---|
| `make test-e2e-istio` | — | Placeholder (not yet implemented) |

### Cross-Tier

| Target | Backend | Description |
|---|---|---|
| `make e2e-teardown-full` | Kind | Tear down all Kind clusters (default + Cilium) |

---

## Cilium Kind Cluster (Tier 2)

Tier 2 tests require a Kind cluster with Cilium as the CNI. The default
CNI is disabled so Cilium can manage pod networking and Hubble can observe
flow drops.

### Prerequisites

- Docker, `kubectl`, `helm`, Go 1.25+, Kind
- ~4GB RAM allocated to Docker

### Workflow

```bash
# Create Cilium Kind cluster + install everything
make e2e-setup-cilium

# Run tests (same test binary — Cilium-specific tests will not skip)
make test-e2e-cilium

# Tear down (deletes the Cilium Kind cluster + all resources)
make e2e-teardown-cilium
```

### What Happens

1. **`make e2e-setup-cilium`** runs `hack/e2e-setup-cilium.sh`:
   - Creates a Kind cluster from `hack/kind-cilium.yaml` (`disableDefaultCNI: true`)
   - Installs Cilium via Helm (version-pinned) with Hubble enabled
   - Waits for Cilium agent and Hubble Relay to be ready
   - Builds and loads Potoo Docker images
   - Installs all CRDs (Potoo, Gatekeeper, Kyverno, Prometheus, Istio)
   - Deploys the Potoo controller via Helm

2. **`make test-e2e-cilium`** runs the same E2E test binary as Tier 1. Tests
   that check for Cilium CRDs will find them present and run instead of
   skipping.

3. **`make e2e-teardown-cilium`** runs `hack/e2e-teardown.sh potoo-cilium`,
   which uninstalls all Helm releases, cleans CRD instances, removes
   namespaces, and deletes the Kind cluster.

---

## Teardown

All teardown targets use `hack/e2e-teardown.sh`, which guarantees no hanging
resources:

- Uninstalls all Helm releases (Potoo, Gatekeeper, Kyverno, Cilium)
- Deletes Potoo CRD instances before CRD deletion (prevents finalizer hangs)
- Removes test namespaces (`potoo-e2e=true` label) with 60s timeout
- Force-removes finalizers on stuck namespaces (requires `jq`)
- Deletes operator namespaces, CRDs, and webhook configurations
- Deletes the Kind cluster and verifies removal

For Docker Desktop (`make e2e-teardown-dd`), the cluster is preserved but all
Potoo state is cleaned. Use `make e2e-teardown-full` to tear down all Kind
clusters at once.

---

## Troubleshooting

### Tests fail with "failed to load kubeconfig"

Ensure `KUBECONFIG` is set or `~/.kube/config` exists. For Kind:

```bash
kind export kubeconfig --name potoo
```

### Controller never becomes ready

```bash
kubectl get pods -n potoo-system
kubectl describe pod -n potoo-system -l app.kubernetes.io/component=controller
kubectl logs -n potoo-system -l app.kubernetes.io/component=controller
```

### Image pull errors

**Docker Desktop:** Verify the image exists locally:

```bash
docker images | grep potoo
```

**Kind:** Ensure images are loaded:

```bash
kind load docker-image ghcr.io/potooio/potoo:dev --name potoo
```

### Kind runs stale controller image after rebuild

Kind nodes cache Docker images by tag. After rebuilding, remove the stale
image from the node before reloading:

```bash
docker exec potoo-control-plane crictl rmi ghcr.io/potooio/potoo:dev
kind load docker-image ghcr.io/potooio/potoo:dev --name potoo
kubectl delete pod -n potoo-system -l app.kubernetes.io/component=controller
```

If Docker's build cache is also stale (`COPY . .` showing `CACHED` for changed
source files), add `--no-cache`:

```bash
docker build --no-cache -t ghcr.io/potooio/potoo:dev .
```

### RBAC errors in controller logs

The Helm chart's RBAC grants cluster-wide read access. If you see `forbidden`
errors for patch operations on workloads in other namespaces, this is expected
on a shared cluster — the service account only has patch access to namespaces
where Potoo is deployed. E2E tests use their own labeled namespace.
