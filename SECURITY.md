# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

As an alpha project, we support the latest release only. Once we reach 1.0, we will maintain security patches for the current and previous minor versions.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report vulnerabilities via GitHub's private security advisory feature:

1. Go to the [Security Advisories](https://github.com/potooio/potoo/security/advisories) page
2. Click "New draft security advisory"
3. Fill in the details of the vulnerability

Alternatively, if you prefer email, contact the maintainers directly (see MAINTAINERS.md or the repository owner's profile).

### What to Include

- Type of vulnerability (e.g., privilege escalation, information disclosure, denial of service)
- Full paths of affected source files
- Steps to reproduce or proof-of-concept
- Impact assessment
- Any suggested fixes (optional but appreciated)

### Response Timeline

- **Initial response**: Within 72 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity (critical: days, high: 1-2 weeks, medium/low: next release)

We will keep you informed throughout the process and credit you in the advisory (unless you prefer to remain anonymous).

## Security Model

Potoo is a **read-only policy observer**, not a policy engine. Key security properties:

### What Potoo Can Access

- **Cluster-wide read access**: Potoo requires `get`, `list`, `watch` on all resources to discover constraints. This is intentional and documented in RBAC manifests.
- **Kubernetes Events**: Creates events in workload namespaces to notify developers.
- **CRD management**: Creates/updates ConstraintReport CRs.

### What Potoo Cannot Do

- **Modify workloads**: No create/update/delete on Pods, Deployments, etc.
- **Modify policies**: No write access to NetworkPolicy, Gatekeeper constraints, etc.
- **Exfiltrate data**: No external network calls except optional Hubble gRPC (cluster-internal).

### Privacy Boundaries

See [docs/PRIVACY_MODEL.md](docs/PRIVACY_MODEL.md) for details on information scoping:

- Developers only see constraints that **directly affect their namespace**
- Cross-namespace policy details are never exposed in notifications
- Constraint names from other namespaces are redacted in developer-facing outputs

### Admission Webhook

The optional admission webhook uses `failurePolicy: Ignore`:

- If the webhook is unavailable, deployments proceed normally
- The webhook **never blocks** workloads — it only annotates them with constraint info
- This is a deliberate security/availability tradeoff

## Security Best Practices for Operators

### RBAC

- Deploy Potoo in a dedicated namespace (e.g., `potoo-system`)
- Use the provided RBAC manifests without modification
- Do not grant Potoo service accounts to developers

### Network Policy

- Potoo only needs:
  - Egress to the Kubernetes API server
  - Egress to Hubble (if enabled, typically `hubble-relay.kube-system:4245`)
  - Ingress for webhook (if enabled, from API server)
  - Ingress for MCP server (if enabled, from authorized agents only)
- Lock down with NetworkPolicy accordingly

### Container Security

- Official images are built from distroless base (`gcr.io/distroless/static:nonroot`)
- Containers run as non-root (UID 65532)
- No shell or package manager in the image
- Images are signed and include SBOM attestations (see CI workflow)

### Secrets

- Potoo does not require any secrets for core functionality
- Slack webhook URLs should be stored in Kubernetes Secrets, not ConfigMaps
- MCP server authentication tokens (if used) should be mounted from Secrets

## Known Limitations

1. **Broad read RBAC**: Required for constraint discovery. Cannot be scoped without losing functionality.
2. **Event visibility**: Kubernetes Events are namespace-scoped but readable by anyone with namespace access.
3. **CRD schemas**: Potoo parses unstructured objects; malformed CRDs may cause parsing errors (not security issues).

## Dependency Management

- Dependencies are pinned in `go.mod` and `go.sum`
- Dependabot is enabled for automated security updates
- Container images are rebuilt weekly to pick up base image patches
- SBOM is generated for each release (see `.github/workflows/security.yml`)
