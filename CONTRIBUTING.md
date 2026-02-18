# Contributing to Potoo

Thank you for your interest in contributing! This project is in early development and contributions are welcome.

## Communication

- **Questions & Discussion**: Open a [GitHub Discussion](https://github.com/potooio/potoo/discussions) or Issue
- **Bug Reports**: Use [GitHub Issues](https://github.com/potooio/potoo/issues) with reproduction steps
- **Security Issues**: See [SECURITY.md](SECURITY.md) — do not use public issues

## First-Time Contributors

New to the project? Look for issues labeled [`good first issue`](https://github.com/potooio/potoo/labels/good%20first%20issue) or [`help wanted`](https://github.com/potooio/potoo/labels/help%20wanted).

Good starting points:
- Adding test fixtures for edge cases
- Documentation improvements
- Writing a new adapter (see [docs/ADAPTER_GUIDE.md](docs/ADAPTER_GUIDE.md))

## Development Setup

### Prerequisites

- Go 1.22+
- Docker
- kubectl
- Kind (for local testing)
- Helm 3
- controller-gen (`go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest`)

### Getting Started

```bash
# Clone the repo
git clone https://github.com/potooio/potoo.git
cd potoo

# Install dependencies
go mod download

# Run tests
make test

# Build the binary
make build

# Create a local Kind cluster
make kind-create

# Build and load the image
make kind-load

# Install via Helm
make helm-install
```

### Running Locally (Out-of-Cluster)

```bash
# Uses your current kubeconfig context
make run
```

## Project Structure

```
potoo/
├── api/v1alpha1/           # CRD type definitions
├── cmd/
│   ├── controller/         # Main controller entrypoint
│   └── webhook/            # Admission webhook entrypoint
├── config/
│   ├── crd/                # Generated CRD manifests
│   ├── rbac/               # RBAC manifests
│   └── samples/            # Example CR instances
├── deploy/helm/            # Helm chart
├── docs/                   # Documentation
├── internal/
│   ├── adapters/           # Constraint adapters (one package per engine)
│   │   ├── registry.go     # Adapter registry
│   │   ├── networkpolicy/  # Native NetworkPolicy adapter
│   │   ├── cilium/         # Cilium adapter
│   │   ├── gatekeeper/     # Gatekeeper adapter
│   │   ├── kyverno/        # Kyverno adapter
│   │   ├── istio/          # Istio adapter
│   │   ├── resourcequota/  # ResourceQuota/LimitRange adapter
│   │   ├── webhook/        # ValidatingWebhookConfiguration adapter
│   │   └── generic/        # Fallback adapter for unknown CRDs
│   ├── correlator/         # Failure-to-constraint correlation
│   ├── discovery/          # CRD discovery engine
│   ├── hubble/             # Hubble flow client
│   ├── indexer/            # In-memory constraint index
│   ├── notifier/           # Notification dispatcher
│   ├── requirements/       # Missing resource detection
│   └── types/              # Shared types (Constraint, Adapter interface, etc.)
├── hack/                   # Scripts for development
└── test/
    ├── fixtures/           # Shared test YAML fixtures
    ├── integration/        # envtest-based integration tests
    └── e2e/                # Kind-based end-to-end tests
```

## Writing an Adapter

See [docs/ADAPTER_GUIDE.md](docs/ADAPTER_GUIDE.md) for detailed instructions on writing a new constraint adapter.

The short version:

1. Create a package under `internal/adapters/youradapter/`
2. Implement the `types.Adapter` interface
3. Register it in `cmd/controller/main.go`
4. Write tests with YAML fixtures in `testdata/`
5. Submit a PR

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` (config in `.golangci.yml`)
- Parse Kubernetes objects from `unstructured.Unstructured`, not typed clients
- Handle missing fields defensively — CRD schemas change across versions
- Write clear `Summary` strings — they appear in developer notifications
- Every adapter needs comprehensive test fixtures

## Commit Messages

Use clear, imperative mood messages:

```
Add Istio adapter for AuthorizationPolicy    # Good
Added Istio adapter                          # Bad (past tense)
Istio stuff                                  # Bad (unclear)
```

For larger changes, use a body to explain **why**:

```
Add timeout to discovery rescan loop

Without a timeout, a slow API server could block the entire
rescan cycle indefinitely. Default 30s matches controller-runtime.
```

## Pull Request Process

1. Fork the repo and create a branch from `master`
2. Add tests for any new functionality
3. Run `make test` and `make lint` — both must pass
4. Update documentation if you're changing behavior
5. Write a clear PR description explaining what and why
6. One approval required for merge

## Developer Certificate of Origin

All contributions must include a sign-off indicating you have the right to submit the code under the Apache 2.0 license:

```bash
git commit -s -m "Add new feature"
```

This adds a `Signed-off-by` line to your commit. By signing off, you certify:

1. You wrote the code, or have the right to submit it
2. You have the right to submit it under Apache 2.0
3. You understand this contribution is public and maintained indefinitely

See [developercertificate.org](https://developercertificate.org/) for the full DCO text.

## Reporting Issues

- Use GitHub Issues
- Include: Kubernetes version, installed policy engines, steps to reproduce
- For constraint discovery issues: include the CRD YAML and expected behavior
- **Security vulnerabilities**: Report privately via [SECURITY.md](SECURITY.md)
