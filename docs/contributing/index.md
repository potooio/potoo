---
layout: default
title: Contributing
nav_order: 7
has_children: true
permalink: /docs/contributing/
---

# Contributing
{: .no_toc }

How to set up a development environment and contribute to Potoo.
{: .fs-6 .fw-300 }

---

## Development Setup

### Prerequisites

- Go 1.25+
- Docker (for building images)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) configured with cluster access
- [Helm](https://helm.sh/docs/intro/install/) v3+

### Clone and Build

```bash
git clone https://github.com/potooio/potoo.git
cd potoo
make build
```

### Run Locally

Run the controller outside the cluster against your current kubeconfig:

```bash
make run
```

This starts the controller with leader election disabled.

### Run Tests

```bash
# Unit tests
make test

# Integration tests (requires envtest binaries)
make test-integration

# E2E tests (requires a running cluster — see below)
make e2e
```

---

## Code Quality

All commits must pass these checks:

```bash
gofmt -l .              # Must produce no output
golangci-lint run ./...  # Must produce 0 issues
go test -race ./...      # Must exit 0
```

Run `make lint` as a shortcut for the linter.

---

## Project Structure

```
api/v1alpha1/          CRD types
internal/adapters/     Policy engine adapters (one per sub-package)
internal/controller/   Controller reconcilers
internal/discovery/    CRD scanner and dynamic informers
internal/indexer/      In-memory constraint store
internal/correlator/   Event-to-constraint matcher
internal/notifier/     Notification dispatch and workload annotation
internal/mcp/          MCP server for AI agents
internal/api/          HTTP API
internal/requirements/ Missing-resource detection
internal/hubble/       Optional Hubble gRPC client
cmd/controller/        Main entrypoint
cmd/webhook/           Admission webhook
cmd/potooctl/       CLI tool
test/integration/      Envtest-based integration tests
test/e2e/              End-to-end tests against a real cluster
```

---

## What's Next

- [E2E Testing](e2e-testing.html) - Run end-to-end tests locally
