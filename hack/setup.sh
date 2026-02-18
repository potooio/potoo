#!/usr/bin/env bash
# hack/setup.sh — Install all required development tools.
# Run this before starting development. Idempotent.
set -euo pipefail

echo "=== Checking Go ==="
if ! command -v go &>/dev/null; then
    echo "ERROR: Go is not installed. Install Go 1.22+ from https://go.dev/dl/"
    exit 1
fi
GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1)
echo "Found $GO_VERSION"

echo "=== Installing controller-gen ==="
if ! command -v controller-gen &>/dev/null; then
    go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
    echo "Installed controller-gen"
else
    echo "controller-gen already installed"
fi

echo "=== Installing golangci-lint ==="
if ! command -v golangci-lint &>/dev/null; then
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    echo "Installed golangci-lint"
else
    echo "golangci-lint already installed"
fi

echo "=== Installing Go dependencies ==="
go mod download
echo "Dependencies downloaded"

echo "=== Verifying compilation ==="
if go build ./... 2>/dev/null; then
    echo "Project compiles successfully"
else
    echo "WARNING: Project does not compile yet — this is expected before TASK-0.1 is complete"
fi

echo ""
echo "=== Setup complete ==="
echo "Run 'cat TASKS.md | head -30' to see the first tasks."
echo "Run 'hack/verify.sh all' to check current status."
