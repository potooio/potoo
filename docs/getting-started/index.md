---
layout: default
title: Getting Started
nav_order: 2
has_children: true
permalink: /docs/getting-started/
---

# Getting Started
{: .no_toc }

This section covers everything you need to get Potoo running in your cluster.
{: .fs-6 .fw-300 }

---

## Overview

Potoo consists of three components:

| Component | Description | Required |
|-----------|-------------|----------|
| **Controller** | Watches policies, builds constraint index, sends notifications | Yes |
| **Admission Webhook** | Captures real-time admission events for correlation | Optional |
| **CLI (potoo)** | Query constraints, explain errors, pre-check manifests | Optional |

The controller is the core component. The webhook and CLI add real-time correlation and developer tooling.

---

## Prerequisites

### Kubernetes Cluster

- Kubernetes 1.24 or later
- Helm 3.10 or later
- `kubectl` configured with cluster access

### RBAC Requirements

Potoo needs cluster-wide read access to discover policies:

```yaml
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
```

This is intentional—Potoo must see all policy types to correlate them. The controller never modifies cluster resources (except its own CRDs).

### Optional: Policy Engines

Potoo auto-detects installed policy engines:

| Engine | Detection |
|--------|-----------|
| Cilium | CiliumNetworkPolicy CRD exists |
| Gatekeeper | Constraint CRD exists |
| Kyverno | ClusterPolicy CRD exists |
| Istio | AuthorizationPolicy CRD exists |

Native Kubernetes resources (NetworkPolicy, ResourceQuota, LimitRange) are always watched.

---

## User Roles

Potoo serves different audiences with different information:

### Developers

- See constraints affecting their namespace
- Receive actionable error explanations
- Get remediation guidance (contact info, kubectl commands)
- Cannot see cross-namespace policy details

### Namespace Admins

- See detailed constraint information for their namespace
- See port numbers and effect details
- Still cannot see other namespaces' policies

### Platform Admins

- See all constraints cluster-wide
- See cross-namespace impact analysis
- Access Hubble flow data (if enabled)
- Manage ConstraintProfile and NotificationPolicy CRDs

---

## What's Next

1. [Installation](installation.html) - Install Potoo with Helm
2. [Quickstart](quickstart.html) - 5-minute hands-on tutorial
