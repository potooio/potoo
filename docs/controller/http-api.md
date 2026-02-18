---
layout: default
title: HTTP API
parent: Controller
nav_order: 5
---

# HTTP API Reference
{: .no_toc }

The controller exposes a REST API for health checks, capability discovery, and constraint queries.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

The HTTP API runs on the controller's metrics port (default `8080`) alongside Prometheus metrics and health probes. These endpoints are used internally by the admission webhook and are also available for external integrations.

{: .note }
> For AI agent integration, use the [MCP Server](/docs/mcp/) instead. The HTTP API uses Kubernetes-native camelCase JSON, while MCP uses agent-friendly snake_case. See [JSON Naming Convention](#json-naming-convention) below.

---

## GET /api/v1/capabilities

Returns adapter status, constraint type counts, and feature flags. Used by agents and dashboards for service discovery.

### Response

```json
{
  "version": "1",
  "adapters": [
    {
      "name": "networkpolicy",
      "enabled": true,
      "watchedResources": ["networkpolicies"],
      "constraintCount": 8,
      "errorCount": 0
    },
    {
      "name": "gatekeeper",
      "enabled": false,
      "watchedResources": ["constrainttemplates"],
      "constraintCount": 0,
      "errorCount": 0,
      "reason": "CRDs not installed"
    }
  ],
  "constraintTypes": {
    "NetworkIngress": 3,
    "NetworkEgress": 5,
    "Admission": 4,
    "ResourceLimit": 2
  },
  "totalConstraints": 14,
  "namespaceCount": 6,
  "watchedResources": 12,
  "hubbleStatus": {
    "enabled": true,
    "connected": true,
    "address": "hubble-relay.kube-system.svc:4245"
  },
  "mcpStatus": {
    "enabled": true,
    "transport": "sse",
    "port": 8090
  },
  "lastScanTime": "2024-01-15T10:30:00Z",
  "upSince": "2024-01-15T08:00:00Z"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | API schema version (currently `"1"`) |
| `adapters` | array | Enabled adapter details with constraint counts |
| `constraintTypes` | object | Constraint count by type |
| `totalConstraints` | int | Total indexed constraints |
| `namespaceCount` | int | Namespaces with constraints |
| `watchedResources` | int | Total watched resource types |
| `hubbleStatus` | object | Hubble integration status (omitted if disabled) |
| `mcpStatus` | object | MCP server status (omitted if disabled) |
| `lastScanTime` | string | Last CRD scan timestamp (RFC 3339) |
| `upSince` | string | Controller start time (RFC 3339) |

---

## GET /api/v1/constraints

Returns all indexed constraints, optionally filtered by namespace. Used by the admission webhook to look up constraints at deploy time.

### Query Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `namespace` | No | Filter constraints to a specific namespace |

### Examples

```bash
# All constraints
curl http://potoo-controller:8080/api/v1/constraints

# Constraints for a specific namespace
curl http://potoo-controller:8080/api/v1/constraints?namespace=production
```

### Response

```json
{
  "constraints": [
    {
      "name": "restrict-egress",
      "namespace": "production",
      "constraintType": "NetworkEgress",
      "severity": "Critical",
      "effect": "deny",
      "summary": "Outbound network traffic is restricted by a network policy",
      "source": {
        "group": "networking.k8s.io",
        "version": "v1",
        "resource": "networkpolicies"
      },
      "affectedNamespaces": ["production"],
      "tags": ["network", "egress"]
    }
  ]
}
```

{: .warning }
> This endpoint returns the internal `Constraint` model with camelCase field names. The `RawObject` field is stripped from responses to avoid sending full unstructured Kubernetes objects over the wire.

---

## GET /api/v1/health

Returns controller health status.

### Response

```json
{
  "status": "healthy",
  "indexer": "ready",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Status Values

| Status | Meaning |
|--------|---------|
| `healthy` | Indexer initialized and operational |
| `unhealthy` | Indexer not initialized |

---

## GET /health

Alias for `/api/v1/health`. Used as the liveness probe endpoint.

---

## Port Forwarding

To access the API from outside the cluster:

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8080:8080

curl http://localhost:8080/api/v1/capabilities
curl http://localhost:8080/api/v1/constraints?namespace=production
curl http://localhost:8080/api/v1/health
```

---

## JSON Naming Convention

The HTTP API uses **camelCase** field names (Kubernetes convention), while the [MCP Server](/docs/mcp/) uses **snake_case** (JSON API convention). This is intentional:

| Interface | Convention | Example |
|-----------|-----------|---------|
| HTTP API (`/api/v1/*`) | camelCase | `constraintType`, `lastScanTime` |
| MCP Server | snake_case | `constraint_type`, `last_observed` |
| CRD status fields | camelCase | `constraintCount`, `machineReadable` |

Consumers should use the appropriate interface for their context. The MCP server is preferred for AI agent integration.

---

## OpenAPI

An OpenAPI specification (`/openapi/v3`) is not yet available. The endpoint definitions above serve as the current API reference.
