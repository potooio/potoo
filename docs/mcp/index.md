---
layout: default
title: MCP Server
nav_order: 5
has_children: true
permalink: /docs/mcp/
---

# MCP Server Reference
{: .no_toc }

Potoo exposes an MCP (Model Context Protocol) server for AI agent integration.
{: .fs-6 .fw-300 }

---

## What is MCP?

The Model Context Protocol (MCP) is a standard for AI assistants to interact with external tools and data sources. Potoo's MCP server enables AI coding assistants to:

- Query constraint information
- Explain deployment errors
- Pre-check manifests before deployment
- Provide remediation guidance

---

## Why MCP?

Traditional debugging requires developers to:
1. See an error message
2. Search for related policies
3. Understand policy semantics
4. Figure out remediation

With MCP, AI assistants can do this automatically:

```
Developer: "My deployment is failing with 'connection refused to port 9090'"

AI Assistant: Let me check what constraints affect your namespace.

→ [Calls potoo_explain with the error message]

AI Assistant: I found the issue. There's a NetworkPolicy 'restrict-egress'
in your namespace that only allows egress on ports 443 and 8443.

To fix this, you can either:
1. Request an exception from platform-team@company.com
2. Or change your application to use port 443 instead

Would you like me to draft the exception request?
```

---

## Enabling MCP

### Helm Configuration

```yaml
mcp:
  enabled: true
  port: 8090
  transport: sse  # or "stdio" for local agents
  authentication:
    method: kubernetes-sa
```

### Verify MCP is Running

```bash
# Check the controller has MCP enabled
kubectl logs -n potoo-system -l app=potoo-controller | grep "MCP server"

# Port-forward for local testing
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090
```

---

## Transport Options

### SSE (Server-Sent Events)

Default for remote agents. Agents connect via HTTP.

```yaml
mcp:
  transport: sse
  port: 8090
```

Endpoint: `http://potoo-controller.potoo-system.svc:8090/sse`

### stdio

For local agents running in the same pod or via kubectl exec.

```yaml
mcp:
  transport: stdio
```

---

## Authentication

### Kubernetes ServiceAccount (Default)

Agents in the cluster authenticate via ServiceAccount tokens.

```yaml
mcp:
  authentication:
    method: kubernetes-sa
```

The agent must provide a bearer token from a ServiceAccount.

### Bearer Token

For external agents, configure a static bearer token.

```yaml
mcp:
  authentication:
    method: bearer-token
    # Token stored in a Secret
```

---

## Available Tools

MCP tools are functions that agents can call:

| Tool | Description |
|------|-------------|
| [potoo_query](tools/#potoo_query) | Query constraints in a namespace |
| [potoo_explain](tools/#potoo_explain) | Match error to constraints |
| [potoo_check](tools/#potoo_check) | Pre-check a manifest |
| [potoo_list_namespaces](tools/#potoo_list_namespaces) | List namespaces with constraints |
| [potoo_remediation](tools/#potoo_remediation) | Get remediation for a constraint |

See [Tools Reference](tools/) for details.

---

## Available Resources

MCP resources are data endpoints that agents can read:

| Resource | Path | Description |
|----------|------|-------------|
| [reports](resources/#reports) | `/resources/reports/{namespace}` | Full constraint report |
| [constraints](resources/#constraints) | `/resources/constraints/{namespace}/{name}` | Single constraint |
| [health](resources/#health) | `/resources/health` | Controller health status |
| [capabilities](resources/#capabilities) | `/resources/capabilities` | Enabled features |

See [Resources Reference](resources/) for details.

---

## Privacy and Detail Levels

MCP responses respect the same privacy model as other notification channels:

| Caller Context | Detail Level |
|----------------|--------------|
| In-namespace ServiceAccount | `detailed` |
| Cluster-admin role | `full` |
| External (bearer token) | `summary` (default) |

Constraint names from other namespaces are redacted unless the caller has cluster-admin privileges.

---

## Example Agent Interaction

Here's how an AI agent might use the MCP tools:

```json
// Agent receives: "Why is my pod failing to connect to the database?"

// Step 1: Agent calls potoo_explain
{
  "tool": "potoo_explain",
  "params": {
    "error_message": "connection refused to database:5432",
    "namespace": "my-app"
  }
}

// Response:
{
  "explanation": "This error appears to be network-related.",
  "confidence": "high",
  "matching_constraints": [
    {
      "name": "restrict-egress",
      "constraint_type": "NetworkEgress",
      "severity": "Critical",
      "remediation": {
        "summary": "Request network exception",
        "steps": [...]
      }
    }
  ]
}

// Step 2: Agent calls potoo_remediation for more detail
{
  "tool": "potoo_remediation",
  "params": {
    "constraint_name": "restrict-egress",
    "namespace": "my-app"
  }
}

// Response with detailed remediation steps
```

---

## What's Next

- [Tools Reference](tools/) - Detailed tool documentation
- [Resources Reference](resources/) - Resource endpoint documentation
- [Agent Integration](agent-integration/) - Connect AI assistants
