---
layout: default
title: CLI (potoo)
nav_order: 3
has_children: true
permalink: /docs/cli/
---

# CLI Reference
{: .no_toc }

The `potoo` command-line tool queries constraints and explains errors.
{: .fs-6 .fw-300 }

---

## Installation

### Download Binary

Pre-built binaries are available from [GitHub Releases]({{ site.github_repo_url }}/releases):

```bash
# Linux amd64
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-linux-amd64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/
```

See the [Installation Guide](/docs/getting-started/installation/#cli-installation) for macOS, Windows, and other platforms.

### Using Go

Requires Go 1.21+.

```bash
go install github.com/potooio/potoo/cmd/potooctl@latest
```

### From Source

```bash
git clone https://github.com/potooio/potoo.git
cd potoo
make build
mv bin/potoo /usr/local/bin/
```

### Verify

```bash
potoo version
potoo --help
```

---

## Commands Overview

| Command | Purpose |
|---------|---------|
| [query](query/) | Query constraints affecting a namespace |
| [explain](explain/) | Match an error message to constraints |
| [check](check/) | Pre-check a manifest before deploying |
| [remediate](remediate/) | Get remediation steps for a constraint |
| [status](status/) | Show cluster-wide constraint summary |

---

## Global Flags

All commands accept these flags:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `table` | Output format: `table`, `json`, `yaml` |
| `--help` | `-h` | | Show help for command |
| `--version` | | | Show version |

---

## Output Formats

### Table (Default)

Human-readable tabular output:

```bash
potoo query -n my-namespace
```

```
NAMESPACE     NAME             TYPE           SEVERITY   EFFECT
my-namespace  restrict-egress  NetworkEgress  Critical   deny
my-namespace  compute-quota    ResourceLimit  Warning    limit
```

### JSON

Structured JSON matching MCP response schemas:

```bash
potoo query -n my-namespace -o json
```

```json
{
  "namespace": "my-namespace",
  "constraints": [
    {
      "name": "restrict-egress",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "NetworkPolicy",
      "source_api_version": "networking.k8s.io/v1",
      "tags": ["network", "egress"],
      "detail_level": "summary",
      "last_observed": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### YAML

YAML output for readability:

```bash
potoo query -n my-namespace -o yaml
```

```yaml
namespace: my-namespace
constraints:
  - name: restrict-egress
    constraint_type: NetworkEgress
    severity: Critical
    effect: deny
total: 1
```

---

## Data Source

The CLI reads data directly from ConstraintReport CRDs in the cluster. It does not require the Potoo controller to be running, but the reports must have been created by the controller.

```bash
# The CLI reads from:
kubectl get constraintreport -n <namespace>
```

---

## RBAC Requirements

The CLI requires read access to ConstraintReport CRDs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: potoo-cli-user
rules:
  - apiGroups: ["potoo.io"]
    resources: ["constraintreports"]
    verbs: ["get", "list"]
```

For namespace-scoped access, use a Role instead of ClusterRole.

---

## kubectl Plugin Alternative

The CLI can also be invoked as a kubectl plugin:

```bash
# Install
go install github.com/potooio/potoo/cmd/kubectl-sentinel@latest

# Use (identical commands)
kubectl sentinel query -n my-namespace
kubectl sentinel explain -n my-namespace "connection refused"
kubectl sentinel check -f deployment.yaml
```

The kubectl plugin shares the same codebase and accepts the same flags.
