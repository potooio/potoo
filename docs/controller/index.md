---
layout: default
title: Controller
nav_order: 4
has_children: true
permalink: /docs/controller/
---

# Controller Reference
{: .no_toc }

The Potoo controller is the core component that discovers constraints and sends notifications.
{: .fs-6 .fw-300 }

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Potoo Controller                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Discovery  │───▶│   Indexer    │───▶│   Notifier   │      │
│  │   (Watches)  │    │  (In-Memory) │    │  (Dispatch)  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Adapters   │    │  Correlator  │    │     MCP      │      │
│  │ (Parse CRDs) │    │  (Events)    │    │   Server     │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Discovery** | Watches Kubernetes API for policy CRDs |
| **Adapters** | Parse each policy type into normalized Constraint model |
| **Indexer** | In-memory index of constraints by namespace/labels/type |
| **Correlator** | Watches K8s Events to match errors with constraints |
| **Notifier** | Renders and dispatches notifications |
| **MCP Server** | Exposes constraint data to AI agents |

---

## Deployment Model

### Controller (Required)

The main controller runs as a Deployment with leader election:

- **Replicas**: 2 (default) for high availability
- **Leader Election**: One active, one standby
- **Failover**: Automatic when leader pod terminates

### Admission Webhook (Optional)

A separate Deployment handles admission events:

- **Purpose**: Real-time admission event correlation
- **Failure Policy**: Always `Ignore` (never blocks deployments)
- **Separate Binary**: Minimal attack surface

---

## How Discovery Works

1. **CRD Scan**: On startup, scans for installed policy CRDs
2. **Adapter Registration**: Matches CRDs to built-in adapters
3. **Dynamic Informers**: Creates informers for each watched resource
4. **Periodic Rescan**: Checks for newly installed CRDs (`rescanInterval`)

```
Startup
   │
   ▼
┌──────────────────────┐
│  Scan installed CRDs │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│  Match to adapters   │
│  - networkpolicy     │
│  - resourcequota     │
│  - cilium            │
│  - gatekeeper        │
│  - kyverno           │
│  - istio             │
│  - generic           │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│  Start informers     │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│  Watch for changes   │──────┐
└──────────────────────┘      │
   ▲                          │
   │     (rescanInterval)     │
   └──────────────────────────┘
```

---

## Constraint Lifecycle

1. **Create/Update**: Policy resource changes in cluster
2. **Parse**: Adapter converts to normalized Constraint
3. **Index**: Constraint stored in memory index
4. **Match**: Indexed by namespace, labels, type
5. **Notify**: Changes trigger notifications
6. **Report**: ConstraintReport CRD updated

---

## Resource Requirements

| Component | CPU Request | Memory Request | CPU Limit | Memory Limit |
|-----------|-------------|----------------|-----------|--------------|
| Controller | 100m | 256Mi | 500m | 512Mi |
| Webhook | 50m | 128Mi | 200m | 256Mi |

These are defaults for moderate clusters. Increase for:
- Clusters with many policies (>500)
- High policy churn rate
- Large namespace count (>100)

---

## Metrics

The controller exposes Prometheus metrics on port 8080:

| Metric | Type | Description |
|--------|------|-------------|
| `potoo_constraints_total` | Gauge | Total constraints in index |
| `potoo_constraints_by_type` | Gauge | Constraints by type |
| `potoo_constraints_by_severity` | Gauge | Constraints by severity |
| `potoo_adapter_parse_errors` | Counter | Parse failures by adapter |
| `potoo_notifications_sent` | Counter | Notifications by channel |
| `potoo_rescan_duration_seconds` | Histogram | CRD rescan duration |

---

## Health Endpoints

| Endpoint | Port | Description |
|----------|------|-------------|
| `/healthz` | 8080 | Liveness probe |
| `/readyz` | 8080 | Readiness probe |
| `/metrics` | 8080 | Prometheus metrics |

---

## What's Next

- [Configuration](configuration/) - Helm values reference
- [Adapters](adapters/) - Enable/disable policy engines
- [Missing Resources](missing-resources/) - Detection of missing companion resources
- [Notifications](notifications/) - Slack, webhooks, Events
- [Admission Webhook](webhook/) - Deploy-time warnings
- [HTTP API](http-api/) - REST API endpoints for capabilities, constraints, and health
