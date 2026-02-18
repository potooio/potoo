---
layout: default
title: Home
nav_order: 1
description: "Potoo discovers all constraints affecting your Kubernetes workloads and explains them to developers."
permalink: /docs/
---

<div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
  <img src="{{ '/assets/images/potoo-xparent.png' | relative_url }}" alt="Potoo" style="height: 100px; filter: invert(1);">
  <h1 class="fs-9" style="margin: 0;">Potoo</h1>
</div>

Automatic constraint discovery and explanation for Kubernetes.
{: .fs-6 .fw-300 }

[Get Started](/docs/getting-started/){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub]({{ site.github_repo_url }}){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What is Potoo?

> *In the dark, catching bugs before they bite.*

Potoo is a Kubernetes operator that **discovers all constraints** affecting your workloads—network policies, admission policies, resource quotas, service mesh rules, and more—and **explains them to developers** when things go wrong.

It's not a policy engine. It's a policy *explainer*.

### The Problem

Developers see cryptic errors:

```
Error: connection timed out
Error: admission webhook denied the request
Error: exceeded quota
```

Finding the cause means searching across NetworkPolicies, Gatekeeper constraints, Kyverno policies, Istio AuthorizationPolicies, ResourceQuotas, LimitRanges, and countless other CRDs. Even experienced platform engineers struggle to trace these issues.

### The Solution

Potoo watches all policy-related resources in your cluster, correlates them to workloads, and provides clear explanations:

```bash
$ potoo explain -n my-namespace "connection timed out"

Explanation: This error appears to be network-related.
Confidence: high

Matching Constraints:
  - restrict-egress (NetworkPolicy) - Severity: Critical
    Effect: Restricts egress to ports 443, 8443 only

Remediation:
  1. Request exception from platform-team@company.com
  2. Or add your workload to the allow list
```

---

## Key Features

### Universal Constraint Discovery

Potoo discovers constraints from:

- **Kubernetes native**: NetworkPolicy, ResourceQuota, LimitRange
- **Cilium**: CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy
- **Gatekeeper**: Constraints, ConstraintTemplates
- **Kyverno**: ClusterPolicy, Policy
- **Istio**: AuthorizationPolicy, PeerAuthentication
- **Webhooks**: ValidatingWebhookConfiguration, MutatingWebhookConfiguration
- **Custom CRDs**: Register any policy CRD via ConstraintProfile

### Developer-Friendly Notifications

When constraints block workloads, developers receive actionable notifications:

- **Kubernetes Events** on affected workloads
- **ConstraintReport CRDs** per namespace
- **Slack/webhook** integration for external alerting
- **Workload annotations** with constraint summaries

### Privacy-Aware Design

Multi-tenant clusters need information boundaries. Potoo's [privacy model](/docs/reference/privacy/) ensures:

- Developers see what they need to unblock themselves
- Cross-namespace policy details stay hidden
- Platform admins see the full picture

### AI Agent Integration

Potoo exposes an MCP (Model Context Protocol) server for AI coding assistants:

```
Claude: "My deployment is failing with 'connection refused'. Can you help?"

→ potoo_explain: Matches to NetworkPolicy blocking egress on port 9090
→ potoo_remediation: Provides kubectl command to request exception
```

### Pre-Flight Checks

Validate manifests before deploying:

```bash
$ potoo check -f deployment.yaml

Would Block: true
Blocking Constraints:
  - require-resource-limits (Admission) - Severity: Critical
    Effect: Rejects pods without resource limits

Warnings:
  - restrict-egress: Egress will be limited to ports 443, 8443
```

---

## Quick Install

```bash
helm repo add potoo https://potoo.io/charts
helm install potoo potoo/potoo -n potoo-system --create-namespace
```

Then install the CLI:

```bash
# Download binary (Linux amd64)
curl -sL https://github.com/potooio/docs/releases/latest/download/potooctl-linux-amd64 -o potoo
chmod +x potoo
sudo mv potoo /usr/local/bin/

# Or via Go (requires Go 1.21+)
# go install github.com/potooio/docs/cmd/potooctl@latest
```

See the [Installation Guide](/docs/getting-started/installation/) for macOS, Windows, and other platforms.

---

## How It Works

1. **Discovery**: Potoo watches all policy-related CRDs in the cluster
2. **Parsing**: Adapters normalize each policy type into a common `Constraint` model
3. **Indexing**: Constraints are indexed by namespace, labels, and type
4. **Correlation**: When errors occur, Potoo matches them to relevant constraints
5. **Notification**: Developers receive privacy-scoped explanations with remediation steps

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ NetworkPolicy│───▶│              │    │ Kubernetes  │
│ ResourceQuota│───▶│   Potoo   │───▶│   Events    │
│ Gatekeeper  │───▶│  Controller  │───▶│ConstraintRpt│
│ Kyverno     │───▶│              │───▶│ Slack/Hook  │
│ Istio       │───▶│              │    │ Annotations │
└─────────────┘    └──────────────┘    └─────────────┘
        ▲                  │
        │                  ▼
   ┌────┴────┐      ┌──────────────┐
   │ Hubble  │      │  MCP Server  │◀───── AI Agents
   │ (flows) │      │  CLI/kubectl │◀───── Developers
   └─────────┘      └──────────────┘
```

---

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](/docs/getting-started/) | Installation, prerequisites, quickstart |
| [CLI Reference](/docs/cli/) | potoo query, explain, check, remediate, status |
| [Controller](/docs/controller/) | Configuration, adapters, notifications |
| [MCP Server](/docs/mcp/) | AI agent integration |
| [CRDs](/docs/crds/) | ConstraintReport, ConstraintProfile, NotificationPolicy |
| [Reference](/docs/reference/) | Constraint types, severity levels |
| [Contributing](/docs/contributing/) | Development setup, E2E testing |

---

## Community

- [GitHub Issues]({{ site.github_repo_url }}/issues) - Bug reports and feature requests
- [GitHub Discussions]({{ site.github_repo_url }}/discussions) - Questions and community chat
