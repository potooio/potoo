#!/usr/bin/env bash
# hack/e2e-teardown.sh — Robust E2E environment teardown.
#
# Guarantees: no hanging namespaces, no orphaned CRD instances, no leftover
# Kind clusters. Every step is guarded so teardown never fails.
#
# Usage:
#   hack/e2e-teardown.sh [CLUSTER_NAME] [--skip-cluster-delete]
#
# Arguments:
#   CLUSTER_NAME          Kind cluster name (default: potoo)
#   --skip-cluster-delete Skip Kind cluster deletion (for Docker Desktop)
#
# Prerequisites: kubectl, helm, kind (unless --skip-cluster-delete)
#   jq is optional — used for stuck-namespace finalizer removal.
#
# Examples:
#   hack/e2e-teardown.sh                                       # Tear down default "potoo" Kind cluster
#   hack/e2e-teardown.sh potoo-cilium                       # Tear down Cilium Kind cluster
#   hack/e2e-teardown.sh --skip-cluster-delete                 # Docker Desktop: clean resources, keep cluster
#   hack/e2e-teardown.sh potoo --skip-cluster-delete        # Explicit cluster name + skip deletion

set -uo pipefail
# Note: set -e is intentionally omitted — every step is guarded and teardown
# must complete even when individual commands fail.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Parse arguments (flags first, then positional) ───────────────────────────
CLUSTER_NAME="potoo"
SKIP_CLUSTER_DELETE=false
NS_TERMINATION_TIMEOUT=60

for arg in "$@"; do
    case "$arg" in
        --skip-cluster-delete) SKIP_CLUSTER_DELETE=true ;;
        --*) ;; # ignore unknown flags
        *) CLUSTER_NAME="$arg" ;;
    esac
done

log() { echo "--- [teardown] $*"; }
warn() { echo "--- [teardown] WARNING: $*" >&2; }

# ── 1. Uninstall Helm releases ──────────────────────────────────────────────
log "Uninstalling Helm releases..."
helm uninstall potoo --namespace potoo-system 2>/dev/null || true
helm uninstall kyverno --namespace kyverno-system 2>/dev/null || true
helm uninstall gatekeeper --namespace gatekeeper-system 2>/dev/null || true
helm uninstall cilium --namespace kube-system 2>/dev/null || true

# ── 2. Delete Potoo CRD instances before CRD deletion ────────────────────
# CRDs with finalizers will hang on deletion if instances still exist.
log "Cleaning up Potoo CRD instances..."
for crd_name in $(kubectl get crd -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n' | grep 'potoo\.io' || true); do
    resource=$(kubectl get crd "$crd_name" -o jsonpath='{.spec.names.plural}' 2>/dev/null || true)
    if [ -n "$resource" ]; then
        kubectl delete "$resource" --all --all-namespaces 2>/dev/null || true
    fi
done

# ── 3. Delete test namespaces ────────────────────────────────────────────────
log "Deleting test namespaces (potoo-e2e=true)..."
kubectl delete ns -l potoo-e2e=true --timeout="${NS_TERMINATION_TIMEOUT}s" 2>/dev/null || true

# ── 4. Force-remove finalizers on stuck namespaces ───────────────────────────
# Only targets namespaces with the potoo-e2e label to avoid touching user namespaces.
log "Checking for stuck namespaces..."
stuck_ns=$(kubectl get ns -l potoo-e2e=true -o jsonpath='{.items[?(@.status.phase=="Terminating")].metadata.name}' 2>/dev/null || true)
if [ -n "$stuck_ns" ]; then
    warn "Found stuck namespaces: $stuck_ns"
    if command -v jq >/dev/null 2>&1; then
        for ns in $stuck_ns; do
            log "Removing finalizers from namespace $ns..."
            kubectl get ns "$ns" -o json 2>/dev/null \
                | jq '.spec.finalizers = []' \
                | kubectl replace --raw "/api/v1/namespaces/$ns/finalize" -f - 2>/dev/null || true
        done
    else
        warn "jq not found — cannot remove finalizers from stuck namespaces."
        warn "Install jq or manually delete: $stuck_ns"
    fi
    # Wait briefly for API server to process.
    sleep 5
fi

# ── 5. Delete operator namespaces ────────────────────────────────────────────
log "Deleting operator namespaces..."
kubectl delete ns potoo-system 2>/dev/null || true
kubectl delete ns kyverno-system 2>/dev/null || true
kubectl delete ns gatekeeper-system 2>/dev/null || true

# ── 6. Delete CRDs ──────────────────────────────────────────────────────────
# Delete by name to avoid hanging on network fetches during teardown.
log "Deleting CRDs..."
# Potoo CRDs (instances already cleaned up in step 2).
kubectl delete -f "$ROOT_DIR/config/crd/" 2>/dev/null || true
# Istio CRDs.
kubectl delete crd \
    authorizationpolicies.security.istio.io \
    destinationrules.networking.istio.io \
    envoyfilters.networking.istio.io \
    gateways.networking.istio.io \
    peerauthentications.security.istio.io \
    requestauthentications.security.istio.io \
    serviceentries.networking.istio.io \
    sidecars.networking.istio.io \
    telemetries.telemetry.istio.io \
    virtualservices.networking.istio.io \
    wasmplugins.extensions.istio.io \
    workloadentries.networking.istio.io \
    workloadgroups.networking.istio.io \
    2>/dev/null || true
# Prometheus Operator CRDs.
kubectl delete crd \
    servicemonitors.monitoring.coreos.com \
    podmonitors.monitoring.coreos.com \
    2>/dev/null || true

# ── 7. Clean up orphaned webhook configurations ─────────────────────────────
log "Cleaning up webhook configurations..."
kubectl delete validatingwebhookconfigurations potoo-webhook 2>/dev/null || true
kubectl delete mutatingwebhookconfigurations -l app.kubernetes.io/part-of=potoo 2>/dev/null || true

# ── 8. Delete Kind cluster ──────────────────────────────────────────────────
if [ "$SKIP_CLUSTER_DELETE" = true ]; then
    log "Skipping Kind cluster deletion (--skip-cluster-delete)."
else
    log "Deleting Kind cluster '$CLUSTER_NAME'..."
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

    # Verify the cluster is gone.
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Kind cluster '$CLUSTER_NAME' still exists after deletion attempt."
        warn "Retrying..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    fi

    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Kind cluster '$CLUSTER_NAME' could not be deleted. Manual cleanup required."
    else
        log "Kind cluster '$CLUSTER_NAME' deleted."
    fi
fi

log "Teardown complete."
exit 0
