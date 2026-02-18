# E2E Tests

End-to-end tests run against a real Kubernetes cluster to validate Potoo's
full lifecycle: constraint discovery, event emission, and workload annotation.

## Test Tiers

E2E tests are organized into tiers based on infrastructure requirements:

| Tier | Target | Cluster | Requirements | What It Tests |
|---|---|---|---|---|
| **1** (default) | `make test-e2e` | Docker Desktop or basic Kind | CRDs only, ~3GB RAM | Core discovery, native adapters, Gatekeeper, Kyverno, Istio (CRDs-only), generic adapter, correlation, webhook, MCP, missing resources |
| **2** (Cilium) | `make test-e2e-cilium` | Kind with Cilium CNI | Cilium + Hubble, ~4GB RAM | CiliumNetworkPolicy, Hubble flow-drop detection, L7 policy, graceful degradation |
| **3** (Istio) | `make test-e2e-istio` | Kind with Istio control plane | istiod running, ~5GB RAM | *Placeholder — not yet implemented* |

**Tier 1** runs on every developer machine. Adapters that need external
infrastructure (Cilium CNI, Istio control plane) are skipped gracefully via
`requireXXXInstalled()` helpers when their CRDs are absent.

**Tier 2** requires a Kind cluster with Cilium as the CNI (replacing the
default). See [Cilium Setup](#cilium-kind-cluster-tier-2) below.

**Tier 3** is reserved for future Istio control plane tests. The current Istio
adapter E2E tests run as Tier 1 (CRDs-only, no istiod).

## Quick Start — Docker Desktop (Tier 1)

Docker Desktop's built-in Kubernetes shares the local Docker daemon, so
locally-built images are available immediately (`pullPolicy=Never`).

```bash
# 1. Enable Kubernetes in Docker Desktop settings, then verify:
kubectl cluster-info

# 2. Build images, install CRDs, deploy controller
make e2e-setup-dd

# 3. Run E2E tests
make e2e

# 4. Tear down (removes all Potoo state, preserves your cluster)
make e2e-teardown-dd
```

## Quick Start — Kind (Tier 1)

Kind creates a disposable cluster in Docker containers. Complete isolation,
clean teardown.

```bash
# 1. Build images, create Kind cluster, install CRDs, deploy controller
make e2e-setup

# 2. Run E2E tests
make e2e

# 3. Tear down (deletes the entire Kind cluster + all resources)
make e2e-teardown
```

## Cilium Kind Cluster (Tier 2)

Tier 2 tests require Cilium as the CNI, which means a dedicated Kind cluster
with the default CNI disabled.

```bash
# 1. Create Cilium Kind cluster, install Cilium + Hubble, deploy controller
make e2e-setup-cilium

# 2. Run E2E tests (same test binary, Cilium-specific tests will not skip)
make test-e2e-cilium

# 3. Tear down (deletes the Cilium Kind cluster + all resources)
make e2e-teardown-cilium
```

The setup uses `hack/kind-cilium.yaml` (disables default CNI) and
`hack/e2e-setup-cilium.sh` (installs Cilium via Helm with pinned version).

## Makefile Targets

| Target | Tier | Backend | Description |
|---|---|---|---|
| `make e2e-setup-dd` | 1 | Docker Desktop | Build images, install CRDs, deploy controller |
| `make e2e-teardown-dd` | 1 | Docker Desktop | Clean all state, preserve cluster |
| `make e2e-setup` | 1 | Kind | Create Kind cluster, build/load images, deploy |
| `make e2e-teardown` | 1 | Kind | Delete Kind cluster and all resources |
| `make e2e` / `make test-e2e` | 1 | Any | Run Tier 1 E2E tests |
| `make e2e-setup-cilium` | 2 | Kind (Cilium) | Create Cilium Kind cluster, deploy everything |
| `make e2e-teardown-cilium` | 2 | Kind (Cilium) | Delete Cilium Kind cluster and all resources |
| `make test-e2e-cilium` | 2 | Kind (Cilium) | Run Tier 2 E2E tests |
| `make test-e2e-istio` | 3 | — | Placeholder (not yet implemented) |
| `make e2e-teardown-full` | All | Kind | Tear down all Kind clusters (default + Cilium) |

## Teardown

All teardown targets use `hack/e2e-teardown.sh`, which guarantees complete
cleanup:

- Uninstalls all Helm releases (Potoo, Gatekeeper, Kyverno, Cilium)
- Deletes Potoo CRD instances before CRD deletion (prevents finalizer hangs)
- Removes test namespaces (`potoo-e2e=true` label) with 60s timeout
- Force-removes finalizers on stuck namespaces (requires `jq`)
- Deletes operator namespaces, CRDs, and webhook configurations
- Deletes the Kind cluster and verifies removal

For Docker Desktop (`make e2e-teardown-dd`), the cluster is preserved but all
Potoo state is cleaned.

## Test Structure

```
test/e2e/
  suite_test.go            # TestMain: shared K8s clients, controller readiness wait
  helpers_test.go          # Shared helpers (polling, namespace creation, assertions)
  discovery_test.go        # Core discovery: NetworkPolicy, ResourceQuota, LimitRange, webhooks
  correlation_test.go      # Event correlation: notifications, deduplication, privacy, rate limiting
  constraint_report_test.go # ConstraintReport CRUD, severity counts, machine-readable format
  gatekeeper_test.go       # Gatekeeper adapter: constraints, templates, deletion lifecycle
  kyverno_test.go          # Kyverno adapter: ClusterPolicy, Policy, multi-rule parsing
  istio_test.go            # Istio adapter (CRDs-only): AuthorizationPolicy, PeerAuth, Sidecar
  webhook_test.go          # Admission webhook: warnings, fail-open, TLS, PDB
  cluster_scoped_test.go   # Cluster-scoped constraint annotation
  requirements_test.go     # Missing resource detection: Prometheus, Istio, cert-manager
  generic_adapter_test.go  # Generic adapter + ConstraintProfile lifecycle
  mcp_test.go              # MCP server: health, capabilities, constraint queries
  cilium_test.go           # Cilium adapter: CNP/CCNP discovery, L7, deny-all, Hubble flow drops
```

All files use the `//go:build e2e` tag, so they are excluded from `make test`.

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig file. Kind sets this automatically. |

The test suite uses `controller-runtime`'s config resolution, which checks
`KUBECONFIG`, then `~/.kube/config`, then in-cluster config.

## Troubleshooting

**Tests fail with "failed to load kubeconfig"**
- Ensure `KUBECONFIG` points to a valid file, or `~/.kube/config` exists
- For Kind: `kind export kubeconfig --name potoo`

**Controller never becomes ready**
- Check pod status: `kubectl get pods -n potoo-system`
- Check pod events: `kubectl describe pod -n potoo-system -l app.kubernetes.io/component=controller`
- Check logs: `kubectl logs -n potoo-system -l app.kubernetes.io/component=controller`

**Image pull errors (Docker Desktop)**
- Ensure `pullPolicy=Never` is set (the `e2e-setup-dd` target handles this)
- Verify image exists: `docker images | grep potoo`

**Image pull errors (Kind)**
- Ensure images are loaded: `kind load docker-image ghcr.io/potooio/potoo:dev --name potoo`
- Verify: `docker exec potoo-control-plane crictl images | grep potoo`

**Kind loads image but pod runs stale version**

Kind nodes cache images. If you rebuild your Docker image (same tag) and
`kind load docker-image` it, the node may still use the cached version.
Verify with:

```bash
# Check what the node actually has
docker exec potoo-control-plane crictl images | grep potoo

# If stale, remove the old image from the node and reload
docker exec potoo-control-plane crictl rmi ghcr.io/potooio/potoo:dev
kind load docker-image ghcr.io/potooio/potoo:dev --name potoo

# Then restart the controller pod
kubectl delete pod -n potoo-system -l app.kubernetes.io/component=controller
```

Also ensure Docker itself isn't caching stale build layers. If `COPY . .` shows
`CACHED` when you've changed source files, force a clean build:

```bash
docker build --no-cache -t ghcr.io/potooio/potoo:dev .
```

**Kind fails on WSL2**
- Kind requires cgroup v2. Check: `cat /sys/fs/cgroup/cgroup.controllers`
- If you see "No such file or directory", add to `%USERPROFILE%\.wslconfig`:
  ```
  [wsl2]
  kernelCommandLine = cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1
  ```
- Then: `wsl --shutdown` and restart
- Or use Docker Desktop Kubernetes instead: `make e2e-setup-dd`

**Stale test namespaces**
- Clean up: `kubectl delete ns -l potoo-e2e=true`

**Stuck namespaces in Terminating state**
- Run `make e2e-teardown` (or `e2e-teardown-dd`), which removes finalizers automatically
- Manual fix (requires `jq`):
  ```bash
  kubectl get ns <name> -o json | jq '.spec.finalizers = []' | kubectl replace --raw "/api/v1/namespaces/<name>/finalize" -f -
  ```
