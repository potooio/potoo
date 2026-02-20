---
layout: default
title: CRDs
nav_order: 6
has_children: true
permalink: /docs/crds/
---

# Custom Resource Definitions
{: .no_toc }

Potoo uses three CRDs to store and configure constraint data.
{: .fs-6 .fw-300 }

---

## Overview

| CRD | Scope | Purpose |
|-----|-------|---------|
| [ConstraintReport](constraintreport.html) | Namespaced | Stores discovered constraints per namespace |
| [ConstraintProfile](constraintprofile.html) | Cluster | Configures how CRDs are parsed |
| [NotificationPolicy](notificationpolicy.html) | Cluster | Controls privacy and notification channels |

---

## Installation

CRDs are installed automatically by the Helm chart:

```bash
helm repo add potoo https://potoo.io/charts
helm install potoo potoo/potoo -n potoo-system --create-namespace
```

Verify installation:
```bash
kubectl get crd | grep potoo.io
```

Expected output:
```
constraintprofiles.potoo.io      2024-01-15T10:00:00Z
constraintreports.potoo.io       2024-01-15T10:00:00Z
notificationpolicies.potoo.io    2024-01-15T10:00:00Z
```

---

## CRD Hierarchy

```
                    ┌─────────────────────────┐
                    │  NotificationPolicy     │
                    │  (cluster-scoped)       │
                    │  - Privacy settings     │
                    │  - Channel config       │
                    └───────────┬─────────────┘
                                │
                                │ controls detail level
                                ▼
┌─────────────────────────┐    ┌─────────────────────────┐
│  ConstraintProfile      │    │  ConstraintReport       │
│  (cluster-scoped)       │    │  (namespace-scoped)     │
│  - CRD registration     │───▶│  - Constraint entries   │
│  - Adapter config       │    │  - Machine-readable     │
└─────────────────────────┘    └─────────────────────────┘
```

---

## Who Creates What

| CRD | Created By | When |
|-----|------------|------|
| ConstraintReport | Controller (auto) | When constraints affect a namespace |
| ConstraintProfile | Platform admin (manual) | To register custom policy CRDs |
| NotificationPolicy | Platform admin (manual) | To configure privacy/channels |

---

## RBAC Requirements

### Developers

Read ConstraintReports in their namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: potoo-reader
  namespace: my-namespace
rules:
  - apiGroups: ["potoo.io"]
    resources: ["constraintreports"]
    verbs: ["get", "list"]
```

### Platform Admins

Full access to all Potoo CRDs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: potoo-admin
rules:
  - apiGroups: ["potoo.io"]
    resources: ["*"]
    verbs: ["*"]
```

---

## API Group

All Potoo CRDs use the API group:
```
potoo.io/v1alpha1
```

Full resource names:
- `constraintreports.potoo.io`
- `constraintprofiles.potoo.io`
- `notificationpolicies.potoo.io`

---

## Short Names

| CRD | Short Name | Example |
|-----|------------|---------|
| ConstraintReport | `cr` | `kubectl get cr -n my-namespace` |
| ConstraintProfile | `cp` | `kubectl get cp` |
| NotificationPolicy | `np` | `kubectl get np` |

---

## What's Next

- [ConstraintReport](constraintreport.html) - Per-namespace constraint data
- [ConstraintProfile](constraintprofile.html) - Register custom policy CRDs
- [NotificationPolicy](notificationpolicy.html) - Privacy and channel configuration
