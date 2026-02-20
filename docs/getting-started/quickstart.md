---
layout: default
title: Quickstart
parent: Getting Started
nav_order: 2
---

# Quickstart
{: .no_toc }

A 5-minute hands-on introduction to Potoo.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Prerequisites

- Kubernetes cluster (minikube, kind, or cloud)
- Helm 3.10+
- kubectl configured
- Go 1.21+ (only if installing CLI via `go install`)

---

## Step 1: Install Potoo

```bash
# Add Helm repo and install
helm repo add potoo https://potoo.io/charts
helm install potoo potoo/potoo \
  -n potoo-system \
  --create-namespace

# Wait for pods
kubectl wait --for=condition=ready pod -l app=potoo-controller \
  -n potoo-system --timeout=120s
```

---

## Step 2: Create a Test Namespace with Policies

```bash
# Create namespace
kubectl create namespace quickstart-demo

# Create a NetworkPolicy that restricts egress
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: quickstart-demo
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
          protocol: TCP
EOF

# Create a ResourceQuota
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: quickstart-demo
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 2Gi
    limits.cpu: "4"
    limits.memory: 4Gi
EOF
```

---

## Step 3: View Discovered Constraints

Wait a few seconds for Potoo to discover the policies, then check the ConstraintReport:

```bash
kubectl get constraintreport -n quickstart-demo
```

Output:
```
NAME          CONSTRAINTS   CRITICAL   WARNING   AGE
constraints   2             1          1         30s
```

View details:
```bash
kubectl get constraintreport constraints -n quickstart-demo -o yaml
```

You'll see both the NetworkPolicy and ResourceQuota represented as constraints.

---

## Step 4: Install and Use the CLI

```bash
# Download binary (Linux amd64)
curl -sL https://github.com/potooio/potoo/releases/latest/download/potooctl-linux-amd64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/

# Or via Go (requires Go 1.21+)
# go install github.com/potooio/potoo/cmd/potooctl@latest
```

{: .note }
> See the [Installation Guide](installation.html#cli-installation) for macOS, Windows, and other platforms.

```bash
# Query constraints
potoo query -n quickstart-demo
```

Output:
```
NAMESPACE        NAME             TYPE            SEVERITY   EFFECT
quickstart-demo  restrict-egress  NetworkEgress   Critical   deny
quickstart-demo  compute-quota    ResourceLimit   Warning    limit
```

---

## Step 5: Explain an Error

Simulate a network error and ask Potoo to explain it:

```bash
potoo explain -n quickstart-demo "connection timed out to port 9090"
```

Output:
```
Explanation: This error appears to be network-related. The following
             network policies may be blocking traffic.
Confidence:  high

Matching Constraints:
  NAME             TYPE           SEVERITY   EFFECT
  restrict-egress  NetworkEgress  Critical   deny

Remediation:
  1. [manual] Contact your platform team to request an egress exception
  2. [kubectl] kubectl annotate pod <pod-name> potoo.io/egress-exception=true
```

---

## Step 6: Pre-Check a Deployment

Create a test manifest and check it before deploying:

```bash
cat <<EOF > test-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: quickstart-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: app
          image: nginx
          # Note: no resource limits specified
EOF

potoo check -f test-deployment.yaml
```

Output:
```
Manifest: Deployment/my-app in namespace quickstart-demo

Would Block: false

Warnings:
  - compute-quota: Resource quotas apply. Add resource limits to avoid
    scheduling failures.
  - restrict-egress: Egress will be limited to port 443 only.
```

---

## Step 7: View Cluster Status

See an overview of constraints across all namespaces:

```bash
potoo status
```

Output:
```
NAMESPACE         TOTAL   CRITICAL   WARNING   INFO
quickstart-demo   2       1          1         0
kube-system       0       0          0         0
---
Total: 2 constraints across 1 namespace
Critical: 1, Warning: 1, Info: 0
```

---

## Step 8: JSON Output for Automation

All CLI commands support JSON output for scripting:

```bash
potoo query -n quickstart-demo -o json | jq '.constraints[].name'
```

Output:
```json
"restrict-egress"
"compute-quota"
```

---

## Cleanup

```bash
kubectl delete namespace quickstart-demo
helm uninstall potoo -n potoo-system
kubectl delete namespace potoo-system
```

---

## What's Next?

- [CLI Reference](/docs/cli/) - Full command documentation
- [Controller Configuration](/docs/controller/configuration.html) - Customize behavior
- [MCP Server](/docs/mcp/) - Integrate with AI coding assistants
- [CRDs](/docs/crds/) - Understand the data model
