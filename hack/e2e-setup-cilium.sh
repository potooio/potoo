#!/usr/bin/env bash
# hack/e2e-setup-cilium.sh — Set up a Kind cluster with Cilium CNI for Tier 2 E2E tests.
#
# Creates a Kind cluster using hack/kind-cilium.yaml, installs Cilium as the CNI,
# enables Hubble, loads Potoo images, and deploys the controller.
#
# Usage:
#   hack/e2e-setup-cilium.sh
#
# Prerequisites: docker, kind, kubectl, helm
#
# The Cilium Helm chart version is pinned to avoid breaking changes on release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Pinned versions — update these deliberately, not accidentally.
CILIUM_VERSION="1.16.5"
CILIUM_CHART_VERSION="1.16.5"

IMG="${IMG:-ghcr.io/potooio/potoo:dev}"
WEBHOOK_IMG="${WEBHOOK_IMG:-ghcr.io/potooio/potoo-webhook:dev}"
CLUSTER_NAME="potoo-cilium"

log() { echo "--- [cilium-setup] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Prerequisite checks ─────────────────────────────────────────────────────
for cmd in docker kind kubectl helm; do
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required but not found in PATH."
done

# ── 1. Create Kind cluster ──────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log "Kind cluster '$CLUSTER_NAME' already exists. Reusing."
else
    log "Creating Kind cluster '$CLUSTER_NAME'..."
    kind create cluster --config "$SCRIPT_DIR/kind-cilium.yaml"
fi

# Ensure kubectl targets the correct cluster (critical when reusing an existing cluster).
kubectl config use-context "kind-${CLUSTER_NAME}"

# ── 2. Install Cilium ───────────────────────────────────────────────────────
log "Installing Cilium v${CILIUM_VERSION}..."
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update cilium

helm upgrade --install cilium cilium/cilium \
    --version "$CILIUM_CHART_VERSION" \
    --namespace kube-system \
    --set image.pullPolicy=IfNotPresent \
    --set ipam.mode=kubernetes \
    --set hubble.enabled=true \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=false \
    --wait --timeout 300s

# ── 3. Wait for Cilium readiness ────────────────────────────────────────────
log "Waiting for Cilium pods to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=cilium-agent \
    --namespace kube-system --timeout=120s

kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=hubble-relay \
    --namespace kube-system --timeout=120s

log "Cilium is ready."

# ── 4. Build and load images ────────────────────────────────────────────────
log "Building Docker images..."
make -C "$ROOT_DIR" docker-build-all

log "Loading images into Kind cluster..."
kind load docker-image "$IMG" --name "$CLUSTER_NAME"
kind load docker-image "$WEBHOOK_IMG" --name "$CLUSTER_NAME"

# ── 5. Install CRDs ─────────────────────────────────────────────────────────
log "Installing Potoo CRDs..."
kubectl apply -f "$ROOT_DIR/config/crd/"

log "Installing Gatekeeper..."
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
helm repo update gatekeeper
helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace \
    --wait --timeout 120s

log "Installing Kyverno..."
helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
helm repo update kyverno
helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno-system \
    --create-namespace \
    --wait --timeout 120s

log "Installing Prometheus Operator CRDs..."
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml 2>/dev/null || true
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_podmonitors.yaml 2>/dev/null || true

log "Installing Istio CRDs..."
kubectl apply -f https://raw.githubusercontent.com/istio/istio/1.24.2/manifests/charts/base/files/crd-all.gen.yaml 2>/dev/null || true

# ── 6. Deploy Potoo ──────────────────────────────────────────────────────
log "Deploying Potoo controller..."
helm upgrade --install potoo "$ROOT_DIR/deploy/helm/" \
    --namespace potoo-system \
    --create-namespace \
    --set controller.replicas=1 \
    --set controller.leaderElect=false \
    --set controller.image.tag=dev \
    --set controller.image.pullPolicy=IfNotPresent \
    --set controller.rescanInterval=15s \
    --set controller.annotatorDebounce=5s \
    --set controller.annotatorCacheTTL=5s \
    --set controller.reportDebounce=3s \
    --set requirements.debounceSeconds=10 \
    --set admissionWebhook.enabled=true \
    --set admissionWebhook.replicas=2 \
    --set admissionWebhook.certManagement=self-signed \
    --set admissionWebhook.image.tag=dev \
    --set admissionWebhook.image.pullPolicy=IfNotPresent \
    --set mcp.enabled=true \
    --set hubble.enabled=true \
    --wait --timeout 120s

log "Cilium E2E environment is ready."
log "Run tests with: make test-e2e-cilium"
