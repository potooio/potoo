---
layout: default
title: NotificationPolicy
parent: CRDs
nav_order: 3
---

# NotificationPolicy
{: .no_toc }

Configure privacy scopes and notification channels.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

NotificationPolicy is a cluster-scoped resource that controls:

- What information developers see about constraints
- What information platform admins see
- External notification channels (Slack, webhooks)
- Who is considered a platform admin

**API Version:** `potoo.io/v1alpha1`

**Short Name:** `np`

**Scope:** Cluster

---

## Usage

```bash
# List policies
kubectl get notificationpolicies

# View a policy
kubectl get np default -o yaml

# Create/update a policy
kubectl apply -f notificationpolicy.yaml
```

---

## Spec

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: default
spec:
  # What developers in their own namespace see
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    showAffectedPorts: false
    showRemediationContact: true
    contact: "platform-team@company.com"
    maxDetailLevel: summary

  # What platform admins see
  platformAdminScope:
    showConstraintType: true
    showConstraintName: "all"
    showAffectedPorts: true
    showRemediationContact: true
    contact: ""
    maxDetailLevel: full

  # How to identify platform admins
  platformAdminRoles:
    - cluster-admin
    - platform-admin

  # External notification channels
  channels:
    slack:
      enabled: true
      webhookUrl: "https://hooks.slack.com/services/XXX"
      minSeverity: Critical
    webhook:
      enabled: false
      url: ""
```

---

## Developer Scope

Controls what developers see in their own namespace:

```yaml
developerScope:
  showConstraintType: true
  showConstraintName: "same-namespace-only"
  showAffectedPorts: false
  showRemediationContact: true
  contact: "platform-team@company.com"
  maxDetailLevel: summary
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `showConstraintType` | bool | Include constraint type in notifications |
| `showConstraintName` | enum | Name visibility: none, same-namespace-only, all |
| `showAffectedPorts` | bool | Include port numbers in notifications |
| `showRemediationContact` | bool | Include contact info for remediation |
| `contact` | string | Default contact for manual remediation |
| `maxDetailLevel` | enum | Cap on detail level: summary, detailed, full |

### showConstraintName Values

| Value | Behavior |
|-------|----------|
| `none` | Never show constraint names |
| `same-namespace-only` | Only show names of constraints in the developer's namespace |
| `all` | Show all constraint names (not recommended for multi-tenant) |

### maxDetailLevel Values

| Value | Includes |
|-------|----------|
| `summary` | Type, existence, generic guidance |
| `detailed` | + port numbers, effect details |
| `full` | + cross-namespace policy names, complete details |

---

## Platform Admin Scope

Controls what platform admins see:

```yaml
platformAdminScope:
  showConstraintType: true
  showConstraintName: "all"
  showAffectedPorts: true
  showRemediationContact: true
  maxDetailLevel: full
```

Platform admins typically have unrestricted access to all constraint details.

---

## Platform Admin Identification

How to determine who is a platform admin:

```yaml
platformAdminRoles:
  - cluster-admin
  - platform-admin
  - security-team
```

Users with any of these ClusterRoles are treated as platform admins and receive full-detail notifications.

---

## Notification Channels

### Slack

```yaml
channels:
  slack:
    enabled: true
    webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minSeverity: Critical
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable Slack notifications |
| `webhookUrl` | string | Slack incoming webhook URL |
| `minSeverity` | enum | Minimum severity to notify: Critical, Warning, Info |

### Webhook

```yaml
channels:
  webhook:
    enabled: true
    url: "https://your-service.example.com/potoo-events"
    timeoutSeconds: 10
    insecureSkipVerify: false
    minSeverity: Warning
    authSecretRef:
      name: webhook-auth-token
      key: token
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable webhook notifications |
| `url` | string | | HTTP endpoint to POST events |
| `timeoutSeconds` | int | `10` | HTTP request timeout in seconds |
| `insecureSkipVerify` | bool | `false` | Skip TLS certificate verification (insecure) |
| `minSeverity` | enum | `Warning` | Minimum severity: Critical, Warning, Info |
| `authSecretRef` | object | | Reference to a K8s Secret containing a bearer token |
| `authSecretRef.name` | string | | Secret name in the controller namespace |
| `authSecretRef.key` | string | | Key within the Secret containing the token |

---

## Complete Example

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: production
spec:
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    showAffectedPorts: false
    showRemediationContact: true
    contact: "platform-team@company.com"
    maxDetailLevel: summary

  platformAdminScope:
    showConstraintType: true
    showConstraintName: "all"
    showAffectedPorts: true
    showRemediationContact: true
    maxDetailLevel: full

  platformAdminRoles:
    - cluster-admin
    - platform-admin

  channels:
    slack:
      enabled: true
      webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      minSeverity: Critical
    webhook:
      enabled: true
      url: "https://pagerduty.example.com/potoo"
```

---

## How Scoping Works

### Event Example

Same constraint event, different audiences:

**Developer sees (summary):**
```
Warning: Network egress from your workload 'api-server' is restricted by
a cluster network policy. Your workload cannot reach external services on
the requested port.

Contact platform-team@company.com for exceptions.
```

**Platform admin sees (full):**
```
Warning: CiliumClusterwideNetworkPolicy 'restrict-monitoring-egress' is
blocking egress from pod 'api-server-7b4d9f' (namespace: team-alpha) to
prometheus-server.monitoring.svc:9090.

Policy allows egress only to ports [443, 8443] for pods matching label
'tier=frontend'.

Policy source: /apis/cilium.io/v2/ciliumclusterwidenetworkpolicies/restrict-monitoring-egress
```

### ConstraintReport Rendering

Reports are rendered with the requester's scope:

```bash
# Developer reads report (sees summary)
kubectl get cr -n my-namespace -o yaml

# Platform admin reads same report (sees full detail if they have RBAC)
kubectl get cr -n my-namespace -o yaml
```

The controller renders reports at the `developerScope.maxDetailLevel`. Platform admins can access raw policy resources for full details.

---

## Multiple Policies

If multiple NotificationPolicy resources exist:

1. Policies are sorted alphabetically by name
2. All policies are active simultaneously — a notification is sent to every policy's configured channels if the severity threshold is met
3. The alphabetically-first policy's `developerScope.maxDetailLevel` determines the detail level for K8s Events and ConstraintReports
4. Create a `default` policy as a baseline

Example hierarchy:
```yaml
# Stricter policy for production
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: production-strict
spec:
  # Only applies to namespaces with label env=production
  developerScope:
    showConstraintName: "none"
    maxDetailLevel: summary
---
# Default for other namespaces
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: default
spec:
  developerScope:
    showConstraintName: "same-namespace-only"
    maxDetailLevel: detailed
```

---

## Relationship to Helm Values

NotificationPolicy extends the Helm values configuration:

| Helm Value | NotificationPolicy Equivalent |
|------------|------------------------------|
| `privacy.defaultDeveloperDetailLevel` | `developerScope.maxDetailLevel` |
| `privacy.showCrossNamespacePolicyNames` | `developerScope.showConstraintName` |
| `privacy.showPortNumbers` | `developerScope.showAffectedPorts` |
| `privacy.remediationContact` | `developerScope.contact` |
| `notifications.slack.*` | `channels.slack.*` |
| `notifications.webhook.*` | `channels.webhook.*` |

NotificationPolicy takes precedence when both are configured.

---

## Routing Examples

### Severity-Based Routing

Route critical alerts to PagerDuty, warnings to Slack, and log everything via webhook:

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: tiered-alerts
spec:
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    showAffectedPorts: false
    showRemediationContact: true
    contact: "platform-team@company.com"
    maxDetailLevel: summary

  platformAdminScope:
    showConstraintName: "all"
    showAffectedPorts: true
    maxDetailLevel: full

  platformAdminRoles:
    - cluster-admin
    - platform-admin

  channels:
    webhook:
      enabled: true
      url: "https://pagerduty.example.com/potoo"
      minSeverity: Critical
      authSecretRef:
        name: pagerduty-token
        key: token
    slack:
      enabled: true
      webhookUrl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      minSeverity: Warning
```

### Multi-Channel Setup

Send all constraint notifications to both an internal logging webhook and a Slack channel, with different severity thresholds:

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: multi-channel
spec:
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    maxDetailLevel: detailed

  channels:
    # Log all constraints for audit
    webhook:
      enabled: true
      url: "https://logging.internal.company.com/potoo"
      minSeverity: Info
    # Only alert team on critical issues
    slack:
      enabled: true
      webhookUrl: "https://hooks.slack.com/services/TEAM/CHANNEL/TOKEN"
      minSeverity: Critical
```

### Minimal Privacy-Strict Policy

For highly sensitive namespaces, minimize information exposure:

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: restricted
spec:
  developerScope:
    showConstraintType: false
    showConstraintName: "none"
    showAffectedPorts: false
    showRemediationContact: true
    contact: "security-team@company.com"
    maxDetailLevel: summary
```

---

## Validation

The controller validates NotificationPolicies:

**Valid:**
```yaml
spec:
  developerScope:
    showConstraintName: "same-namespace-only"
    maxDetailLevel: summary
```

**Invalid (unknown enum value):**
```yaml
spec:
  developerScope:
    showConstraintName: "invalid-value"  # Must be none, same-namespace-only, or all
```

---

## Privacy Model Reference

See [Privacy Model](/docs/reference/privacy/) for the complete privacy classification:

| Classification | Developers | Platform Admins |
|----------------|------------|-----------------|
| Constraint exists | Yes | Yes |
| Constraint type | Yes | Yes |
| Same-namespace name | Yes | Yes |
| Cross-namespace name | **No** | Yes |
| Port numbers | Configurable | Yes |
| CIDR ranges | **No** | Yes |
| Policy source code | **No** | Yes |
