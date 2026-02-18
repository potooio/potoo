# Potoo Makefile

# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/potooio/potoo:dev
WEBHOOK_IMG ?= ghcr.io/potooio/potoo-webhook:dev
# Controller-gen tool
CONTROLLER_GEN ?= $(shell which controller-gen 2>/dev/null)

# Go parameters
GOOS ?= linux
GOARCH ?= amd64
GO_BUILD_FLAGS ?= -ldflags="-s -w"

.PHONY: all
all: build

##@ Development

.PHONY: fmt
fmt: ## Run go fmt
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: test
test: fmt vet ## Run unit tests
	go test ./... -coverprofile cover.out -v

.PHONY: test-integration
test-integration: ## Run integration tests (requires envtest)
	go test ./test/integration/... -v -tags=integration

.PHONY: test-e2e
test-e2e: ## Run e2e tests (requires Kind cluster)
	go test ./test/e2e/... -v -tags=e2e -timeout 15m

.PHONY: test-e2e-retry
test-e2e-retry: ## Run e2e tests with one retry for flaky failures (CI-friendly)
	go test ./test/e2e/... -v -tags=e2e -timeout 15m -count=1 || \
		go test ./test/e2e/... -v -tags=e2e -timeout 15m -count=1

.PHONY: test-e2e-skip-flaky
test-e2e-skip-flaky: ## Run e2e tests, skipping known-flaky subtests
	E2E_SKIP_FLAKY=1 go test ./test/e2e/... -v -tags=e2e -timeout 15m

.PHONY: e2e-setup
e2e-setup: docker-build-all ## Create Kind cluster, load images, deploy controller + deps for E2E
	@kind get clusters 2>/dev/null | grep -q potoo || kind create cluster --name potoo
	kubectl apply -f config/crd/
	kind load docker-image $(IMG) --name potoo
	kind load docker-image $(WEBHOOK_IMG) --name potoo
	@echo "--- Installing Gatekeeper ---"
	@helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
	@helm repo update gatekeeper
	helm upgrade --install gatekeeper gatekeeper/gatekeeper \
		--namespace gatekeeper-system \
		--create-namespace \
		--wait --timeout 120s
	@echo "--- Installing Kyverno ---"
	@helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
	@helm repo update kyverno
	helm upgrade --install kyverno kyverno/kyverno \
		--namespace kyverno-system \
		--create-namespace \
		--wait --timeout 120s
	@echo "--- Installing Prometheus Operator CRDs ---"
	kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml 2>/dev/null || true
	kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_podmonitors.yaml 2>/dev/null || true
	@echo "--- Installing Istio CRDs ---"
	kubectl apply -f https://raw.githubusercontent.com/istio/istio/1.24.2/manifests/charts/base/files/crd-all.gen.yaml 2>/dev/null || true
	@echo "--- Installing Potoo ---"
	helm upgrade --install potoo deploy/helm/ \
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
		--wait --timeout 120s

.PHONY: e2e
e2e: test-e2e ## Alias for test-e2e

.PHONY: e2e-teardown
e2e-teardown: ## Tear down E2E environment (Kind cluster, CRDs, deps, test namespaces)
	bash hack/e2e-teardown.sh potoo

.PHONY: e2e-setup-dd
e2e-setup-dd: docker-build-all ## Deploy controller + deps for E2E on Docker Desktop Kubernetes
	kubectl apply -f config/crd/
	@echo "--- Installing Gatekeeper ---"
	@helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
	@helm repo update gatekeeper
	helm upgrade --install gatekeeper gatekeeper/gatekeeper \
		--namespace gatekeeper-system \
		--create-namespace \
		--wait --timeout 120s
	@echo "--- Installing Kyverno ---"
	@helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
	@helm repo update kyverno
	helm upgrade --install kyverno kyverno/kyverno \
		--namespace kyverno-system \
		--create-namespace \
		--wait --timeout 120s
	@echo "--- Installing Prometheus Operator CRDs ---"
	kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml 2>/dev/null || true
	kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_podmonitors.yaml 2>/dev/null || true
	@echo "--- Installing Istio CRDs ---"
	kubectl apply -f https://raw.githubusercontent.com/istio/istio/1.24.2/manifests/charts/base/files/crd-all.gen.yaml 2>/dev/null || true
	@echo "--- Installing Potoo ---"
	helm upgrade --install potoo deploy/helm/ \
		--namespace potoo-system \
		--create-namespace \
		--set controller.replicas=1 \
		--set controller.leaderElect=false \
		--set controller.image.tag=dev \
		--set controller.image.pullPolicy=Never \
		--set controller.rescanInterval=15s \
		--set controller.annotatorDebounce=5s \
		--set controller.annotatorCacheTTL=5s \
		--set controller.reportDebounce=3s \
		--set requirements.debounceSeconds=10 \
		--set admissionWebhook.enabled=true \
		--set admissionWebhook.replicas=2 \
		--set admissionWebhook.certManagement=self-signed \
		--set admissionWebhook.image.tag=dev \
		--set admissionWebhook.image.pullPolicy=Never \
		--set mcp.enabled=true \
		--wait --timeout 120s

.PHONY: e2e-teardown-dd
e2e-teardown-dd: ## Tear down E2E on Docker Desktop (cleans all state, preserves cluster)
	bash hack/e2e-teardown.sh --skip-cluster-delete

##@ E2E Tiers (Tier 1 = default, Tier 2 = Cilium, Tier 3 = Istio)

.PHONY: test-e2e-cilium
test-e2e-cilium: ## Run Tier 2 E2E tests (requires Cilium Kind cluster)
	go test ./test/e2e/... -v -tags=e2e -timeout 20m

.PHONY: test-e2e-istio
test-e2e-istio: ## Run Tier 3 E2E tests (placeholder — not yet implemented)
	@echo "Tier 3 (Istio control plane) E2E tests are not yet implemented."
	@echo "Istio adapter tests run as Tier 1 (CRDs-only) via: make test-e2e"

.PHONY: e2e-setup-cilium
e2e-setup-cilium: ## Create Cilium Kind cluster + deploy controller for Tier 2 E2E
	bash hack/e2e-setup-cilium.sh

.PHONY: e2e-teardown-cilium
e2e-teardown-cilium: ## Tear down Cilium E2E environment (Kind cluster + all resources)
	bash hack/e2e-teardown.sh potoo-cilium

.PHONY: e2e-teardown-full
e2e-teardown-full: ## Tear down ALL E2E environments (default + Cilium clusters)
	bash hack/e2e-teardown.sh potoo
	bash hack/e2e-teardown.sh potoo-cilium

##@ Build

.PHONY: build
build: fmt vet ## Build controller binary
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) \
		-o bin/controller ./cmd/controller/

.PHONY: build-cli
build-cli: fmt vet ## Build potooctl CLI
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) \
		-o bin/potooctl ./cmd/potooctl/

.PHONY: build-webhook
build-webhook: fmt vet ## Build webhook binary
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) \
		-o bin/webhook ./cmd/webhook/

.PHONY: run
run: fmt vet ## Run controller locally (outside cluster)
	go run ./cmd/controller/ --leader-elect=false

##@ Container

.PHONY: docker-build
docker-build: ## Build controller docker image
	docker build --build-arg BINARY=controller -t $(IMG) .

.PHONY: docker-build-webhook
docker-build-webhook: ## Build webhook docker image
	docker build --build-arg BINARY=webhook -t $(WEBHOOK_IMG) .

.PHONY: docker-build-all
docker-build-all: docker-build docker-build-webhook ## Build all docker images

.PHONY: docker-push
docker-push: ## Push controller docker image
	docker push $(IMG)

.PHONY: docker-push-webhook
docker-push-webhook: ## Push webhook docker image
	docker push $(WEBHOOK_IMG)

.PHONY: docker-push-all
docker-push-all: docker-push docker-push-webhook ## Push all docker images

##@ Code Generation

.PHONY: manifests
manifests: controller-gen ## Generate CRD manifests
	$(CONTROLLER_GEN) crd:allowDangerousTypes=true paths="./api/..." output:crd:artifacts:config=config/crd
	cp config/crd/*.yaml deploy/helm/crds/

.PHONY: generate
generate: controller-gen ## Generate deepcopy methods
	$(CONTROLLER_GEN) object paths="./api/..."

.PHONY: controller-gen
controller-gen: ## Download controller-gen if necessary
ifeq ($(CONTROLLER_GEN),)
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
	$(eval CONTROLLER_GEN := $(shell go env GOPATH)/bin/controller-gen)
endif

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the cluster
	kubectl apply -f config/crd/

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the cluster
	kubectl delete -f config/crd/

.PHONY: helm-template
helm-template: ## Render Helm chart templates
	helm template potoo deploy/helm/

.PHONY: helm-install
helm-install: manifests ## Install via Helm
	helm install potoo deploy/helm/ \
		--namespace potoo-system \
		--create-namespace

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade via Helm
	helm upgrade potoo deploy/helm/ \
		--namespace potoo-system

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall via Helm
	helm uninstall potoo --namespace potoo-system

##@ Local Development

.PHONY: kind-create
kind-create: ## Create a Kind cluster for local development
	kind create cluster --name potoo

.PHONY: kind-delete
kind-delete: ## Delete the Kind cluster
	kind delete cluster --name potoo

.PHONY: kind-load
kind-load: docker-build-all ## Load docker images into Kind cluster
	kind load docker-image $(IMG) --name potoo
	kind load docker-image $(WEBHOOK_IMG) --name potoo

##@ Verification (used by hack/verify.sh and agents)

.PHONY: verify
verify: ## Run all verification checks
	bash hack/verify.sh all

.PHONY: verify-phase-0
verify-phase-0: ## Verify Phase 0 completion
	bash hack/verify.sh phase0

.PHONY: verify-phase-1
verify-phase-1: ## Verify Phase 1 completion
	bash hack/verify.sh phase1

.PHONY: setup
setup: ## Install all development tools
	bash hack/setup.sh

##@ Documentation

.PHONY: docs
docs: ## Serve documentation locally at http://localhost:4000/
	docker run --rm -p 4000:4000 -v $(CURDIR)/docs:/site bretfisher/jekyll-serve

##@ Help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
