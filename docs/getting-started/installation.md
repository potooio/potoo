---
layout: default
title: Installation
parent: Getting Started
nav_order: 1
---

# Installation
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Helm Installation

### Add the Helm Repository

```bash
helm repo add potoo https://potoo.io/charts
helm repo update
```

### Install with Default Settings

```bash
helm install potoo potoo/potoo \
  -n potoo-system \
  --create-namespace
```

This installs:
- Controller with 2 replicas (leader election enabled)
- Admission webhook with 2 replicas
- RBAC with cluster-wide read access
- ServiceAccount with necessary permissions

### Verify Installation

```bash
# Check pods are running
kubectl get pods -n potoo-system

# Check CRDs are installed
kubectl get crd | grep potoo

# View controller logs
kubectl logs -n potoo-system -l app=potoo-controller
```

Expected CRDs:
```
constraintreports.potoo.io
constraintprofiles.potoo.io
notificationpolicies.potoo.io
```

---

## Configuration

### Minimal Production Configuration

```yaml
# values.yaml
controller:
  replicas: 2
  leaderElect: true
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

admissionWebhook:
  enabled: true
  replicas: 2
  failurePolicy: Ignore  # MUST be Ignore for safety

notifications:
  kubernetesEvents: true
  constraintReports: true

privacy:
  defaultDeveloperDetailLevel: summary
  remediationContact: "platform-team@yourcompany.com"
```

Install with custom values:

```bash
helm install potoo potoo/potoo \
  -n potoo-system \
  --create-namespace \
  -f values.yaml
```

### Enable Slack Notifications

```yaml
notifications:
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minSeverity: Critical  # Only Critical alerts
```

### Enable MCP Server for AI Agents

```yaml
mcp:
  enabled: true
  port: 8090
  transport: sse
  authentication:
    method: kubernetes-sa
```

### Enable Hubble Integration (Cilium)

```yaml
hubble:
  enabled: true
  relayAddress: hubble-relay.kube-system.svc:4245
```

---

## CLI Installation

### Download Binary

Pre-built binaries are available from [GitHub Releases]({{ site.github_repo_url }}/releases).

**Linux (amd64)**:
```bash
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-linux-amd64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/
```

**Linux (arm64)**:
```bash
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-linux-arm64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/
```

**macOS (Apple Silicon)**:
```bash
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-darwin-arm64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/
```

**macOS (Intel)**:
```bash
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-darwin-amd64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/
```

**Windows (amd64)**:
```powershell
Invoke-WebRequest -Uri https://github.com/potooio/potoo/releases/latest/download/potooctl-windows-amd64.exe -OutFile potoo.exe
Move-Item potoo.exe C:\Windows\System32\
```

**Verify checksum** (optional, replace platform suffix as needed):
```bash
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-linux-amd64.sha256 -o potoo.sha256
sha256sum -c potoo.sha256
```

### Using Go

Requires Go 1.21+.

```bash
go install github.com/potooio/potoo/cmd/potooctl@latest
```

The binary is named `potoo`. Verify installation:

```bash
potoo version
potoo --help
```

### From Source

```bash
git clone https://github.com/potooio/potoo.git
cd potoo
make build
mv bin/potoo /usr/local/bin/
```

### kubectl Plugin (Alternative)

The CLI can also be invoked as a kubectl plugin:

```bash
# Download binary (Linux amd64)
curl -sL https://github.com/potooio/potoo/releases/latest/download/potoo-sentinel-linux-amd64 -o kubectl-sentinel
chmod +x kubectl-sentinel
sudo mv kubectl-sentinel /usr/local/bin/

# Or via Go (requires Go 1.21+)
# go install github.com/potooio/potoo/cmd/kubectl-sentinel@latest

# Use
kubectl sentinel query -n my-namespace
kubectl sentinel explain -n my-namespace "connection refused"
```

---

## RBAC Details

### Controller ClusterRole

The controller requires broad read access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: potoo-controller
rules:
  # Read all resources to discover policies
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]

  # Write Potoo CRDs
  - apiGroups: ["potoo.io"]
    resources: ["constraintreports", "constraintreports/status"]
    verbs: ["create", "update", "patch", "delete"]

  # Create Events on workloads
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
```

### Webhook ClusterRole

The admission webhook has minimal permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: potoo-webhook
rules:
  # Read Potoo CRDs for constraint lookup
  - apiGroups: ["potoo.io"]
    resources: ["constraintreports"]
    verbs: ["get", "list"]
```

---

## High Availability

### Controller HA

With `controller.replicas: 2` and `controller.leaderElect: true`, one controller is active while the other is standby. Failover is automatic.

### Webhook HA

With `admissionWebhook.replicas: 2` and `admissionWebhook.pdb.enabled: true`, the webhook maintains availability during rolling updates.

### Pod Disruption Budgets

```yaml
admissionWebhook:
  pdb:
    enabled: true
    minAvailable: 1
```

---

## Certificate Management

The admission webhook requires TLS certificates.

### Self-Signed (Default)

```yaml
admissionWebhook:
  certManagement: self-signed
```

Potoo generates certificates automatically and rotates them before expiry.

### cert-manager

```yaml
admissionWebhook:
  certManagement: cert-manager
```

Requires cert-manager installed in the cluster. Potoo creates a Certificate resource.

---

## Uninstallation

```bash
# Remove Helm release
helm uninstall potoo -n potoo-system

# Remove CRDs (optional - deletes all ConstraintReports)
kubectl delete crd constraintreports.potoo.io
kubectl delete crd constraintprofiles.potoo.io
kubectl delete crd notificationpolicies.potoo.io

# Remove namespace
kubectl delete namespace potoo-system
```

---

## Troubleshooting

### Controller Not Starting

Check logs:
```bash
kubectl logs -n potoo-system -l app=potoo-controller
```

Common issues:
- **RBAC errors**: Ensure ClusterRole and ClusterRoleBinding are created
- **CRD not found**: Run `helm install` again or check Helm hooks

### No Constraints Discovered

1. Verify adapters are enabled:
   ```bash
   kubectl get constraintprofiles
   ```

2. Check controller logs for adapter errors:
   ```bash
   kubectl logs -n potoo-system -l app=potoo-controller | grep adapter
   ```

3. Verify policy CRDs exist:
   ```bash
   kubectl get crd | grep -E 'networkpolic|gatekeeper|kyverno'
   ```

### Webhook Not Receiving Events

1. Check webhook registration:
   ```bash
   kubectl get validatingwebhookconfiguration potoo-webhook
   ```

2. Verify failurePolicy is `Ignore`:
   ```bash
   kubectl get validatingwebhookconfiguration potoo-webhook -o yaml | grep failurePolicy
   ```

3. Check webhook pod logs:
   ```bash
   kubectl logs -n potoo-system -l app=potoo-webhook
   ```
