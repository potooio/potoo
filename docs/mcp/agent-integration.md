---
layout: default
title: Agent Integration
parent: MCP Server
nav_order: 3
---

# Agent Integration Guide
{: .no_toc }

Connect AI coding assistants and custom agents to Potoo.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Potoo exposes an HTTP API that follows MCP (Model Context Protocol) conventions. Tools are invoked via HTTP POST, resources are read via HTTP GET, and real-time updates stream over Server-Sent Events (SSE).

| Endpoint Pattern | Method | Purpose |
|-----------------|--------|---------|
| `/tools/potoo_*` | POST | Invoke tools (query, explain, check, remediate) |
| `/resources/*` | GET | Read data (reports, constraints, health, capabilities) |
| `/sse` | GET | Stream real-time constraint change events |
| `/mcp/tools` | GET | Discover available tools with input schemas |
| `/mcp/resources` | GET | Discover available resources |

All requests and responses use JSON.

---

## Quick Start

The fastest way to start using Potoo from your local machine:

```bash
# Port-forward the MCP server
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090

# Query constraints in a namespace
curl -s -X POST http://localhost:8090/tools/potoo_query \
  -H 'Content-Type: application/json' \
  -d '{"namespace": "production"}' | jq

# Explain an error
curl -s -X POST http://localhost:8090/tools/potoo_explain \
  -H 'Content-Type: application/json' \
  -d '{"error_message": "connection refused to port 9090", "namespace": "my-app"}' | jq

# Pre-check a manifest
curl -s -X POST http://localhost:8090/tools/potoo_check \
  -H 'Content-Type: application/json' \
  -d '{"manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\n  namespace: production"}' | jq

# Discover available tools
curl -s http://localhost:8090/mcp/tools | jq

# Read health status
curl -s http://localhost:8090/resources/health | jq
```

---

## Claude Desktop

Claude Desktop connects to MCP servers for tool use during conversations.

### SSE Transport (Recommended)

Start port forwarding, then add Potoo to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090
```

```json
{
  "mcpServers": {
    "potoo": {
      "url": "http://localhost:8090/sse",
      "transport": "sse"
    }
  }
}
```

### stdio Transport

For stdio-based connections via kubectl:

```json
{
  "mcpServers": {
    "potoo": {
      "command": "kubectl",
      "args": [
        "exec", "-i", "-n", "potoo-system",
        "deployment/potoo-controller", "--",
        "/app/mcp-server", "--transport=stdio"
      ]
    }
  }
}
```

{: .note }
stdio transport requires the controller binary to support `--transport=stdio` mode. Check your Potoo version for support.

### Example Conversation

```
You: My deployment in the production namespace keeps failing
     with "connection refused to external-api.example.com:443"

Claude: I'll check what constraints might be affecting your deployment.

[Calls potoo_explain]

Claude: I found the issue. There's a network policy called 'restrict-egress'
in the production namespace that only allows egress to specific endpoints.

The policy currently allows:
- DNS (kube-system, port 53)
- Internal services (*.svc.cluster.local)

It does not allow connections to external-api.example.com.

To resolve this, you have two options:

1. Request an exception from platform-team@company.com
2. Route through an egress proxy if available

Would you like me to help draft the exception request?
```

---

## Claude Code

Claude Code can connect to Potoo's MCP server for constraint-aware coding assistance.

### Configuration

Add Potoo to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "potoo": {
      "type": "sse",
      "url": "http://localhost:8090/sse"
    }
  }
}
```

Or start with a command:

```bash
claude mcp add potoo --transport sse http://localhost:8090/sse
```

Then port-forward before starting Claude Code:

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090
```

---

## VS Code with Copilot

GitHub Copilot in VS Code can use MCP servers for context.

### Setup

1. Add Potoo to your VS Code settings (`.vscode/settings.json`):

```json
{
  "mcp": {
    "servers": {
      "potoo": {
        "type": "sse",
        "url": "http://localhost:8090/sse"
      }
    }
  }
}
```

2. Start port forwarding:

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090
```

### Usage

Ask Copilot about deployment issues:

```
@workspace Why is my deployment failing with admission webhook error?
```

Copilot will use Potoo's tools to diagnose the issue.

---

## Custom Agent Integration

Build your own integration using Potoo's HTTP API.

### Tool Discovery

Agents can discover available tools and their schemas:

```bash
curl -s http://localhost:8090/mcp/tools | jq
```

Response:

```json
{
  "tools": [
    {
      "name": "potoo_query",
      "description": "Query constraints affecting a namespace or workload",
      "inputSchema": {
        "type": "object",
        "properties": {
          "namespace": { "type": "string", "description": "Namespace to query" },
          "workload_name": { "type": "string", "description": "Optional workload name filter" },
          "constraint_type": { "type": "string", "description": "Optional constraint type filter" },
          "severity": { "type": "string", "description": "Optional severity filter" },
          "include_remediation": { "type": "boolean", "description": "Include remediation steps" }
        },
        "required": ["namespace"]
      }
    },
    ...
  ]
}
```

### Python Client

```python
import httpx

class PotooClient:
    """Client for Potoo's HTTP API."""

    def __init__(self, base_url="http://localhost:8090", token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(base_url=base_url, headers=headers)

    def discover_tools(self):
        """List available tools and their input schemas."""
        return self.client.get("/mcp/tools").json()

    def query(self, namespace, **filters):
        """Query constraints in a namespace."""
        return self.client.post(
            "/tools/potoo_query",
            json={"namespace": namespace, **filters}
        ).json()

    def explain(self, error_message, namespace, workload_name=None):
        """Explain an error message by matching to constraints."""
        params = {"error_message": error_message, "namespace": namespace}
        if workload_name:
            params["workload_name"] = workload_name
        return self.client.post("/tools/potoo_explain", json=params).json()

    def check(self, manifest_yaml):
        """Pre-check a manifest for blocking constraints and missing prerequisites."""
        return self.client.post(
            "/tools/potoo_check",
            json={"manifest": manifest_yaml}
        ).json()

    def remediation(self, constraint_name, namespace):
        """Get remediation steps for a specific constraint."""
        return self.client.post(
            "/tools/potoo_remediation",
            json={"constraint_name": constraint_name, "namespace": namespace}
        ).json()

    def health(self):
        """Get controller health status."""
        return self.client.get("/resources/health").json()

    def report(self, namespace):
        """Get the full constraint report for a namespace."""
        return self.client.get(f"/resources/reports/{namespace}").json()


# Usage
client = PotooClient()

# Query constraints
result = client.query(namespace="production", severity="Critical")
print(f"Found {result['total']} critical constraints")

# Explain an error
explanation = client.explain(
    "connection refused to port 9090",
    namespace="my-app"
)
print(f"Confidence: {explanation['confidence']}")
for c in explanation["matching_constraints"]:
    print(f"  - {c['name']}: {c['remediation']['summary']}")

# Pre-check a deployment manifest
check = client.check(open("deployment.yaml").read())
if check["would_block"]:
    print("Deployment would be BLOCKED:")
    for c in check["blocking_constraints"]:
        print(f"  - {c['name']}: {c['remediation']['summary']}")
if check.get("missing_prerequisites"):
    print("Missing prerequisites:")
    for mp in check["missing_prerequisites"]:
        print(f"  - {mp['expected_kind']}: {mp['reason']}")
```

### TypeScript Client

```typescript
interface Constraint {
  name: string;
  constraint_type: string;
  severity: "Critical" | "Warning" | "Info";
  effect: string;
  source_kind: string;
  remediation?: {
    summary: string;
    steps: RemediationStep[];
  };
}

interface RemediationStep {
  type: "manual" | "kubectl" | "annotation" | "yaml_patch" | "link";
  description: string;
  command?: string;
  contact?: string;
  url?: string;
  requires_privilege?: string;
  automated: boolean;
}

interface QueryResult {
  namespace: string;
  constraints: Constraint[];
  total: number;
}

interface CheckResult {
  would_block: boolean;
  blocking_constraints: Constraint[];
  missing_prerequisites: MissingPrerequisite[];
  warnings: string[];
}

interface MissingPrerequisite {
  expected_kind: string;
  expected_api_version: string;
  reason: string;
  severity: string;
  for_workload: string;
  remediation?: {
    summary: string;
    steps: RemediationStep[];
  };
}

class PotooClient {
  constructor(
    private baseUrl: string = "http://localhost:8090",
    private token?: string
  ) {}

  private async post<T>(path: string, body: object): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    return response.json();
  }

  private async get<T>(path: string): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const response = await fetch(`${this.baseUrl}${path}`, { headers });
    return response.json();
  }

  /** Discover available tools and their input schemas. */
  discoverTools() {
    return this.get<{ tools: object[] }>("/mcp/tools");
  }

  /** Query constraints in a namespace. */
  query(namespace: string, filters?: Partial<Record<string, string>>) {
    return this.post<QueryResult>("/tools/potoo_query", {
      namespace,
      ...filters,
    });
  }

  /** Explain an error by matching to constraints. */
  explain(errorMessage: string, namespace: string, workloadName?: string) {
    return this.post<{
      explanation: string;
      confidence: "high" | "medium" | "low";
      matching_constraints: Constraint[];
    }>("/tools/potoo_explain", {
      error_message: errorMessage,
      namespace,
      workload_name: workloadName,
    });
  }

  /** Pre-check a manifest for blocking constraints and missing prerequisites. */
  check(manifestYaml: string) {
    return this.post<CheckResult>("/tools/potoo_check", {
      manifest: manifestYaml,
    });
  }

  /** Get a namespace constraint report. */
  report(namespace: string) {
    return this.get<object>(`/resources/reports/${namespace}`);
  }
}

// Usage
const client = new PotooClient();

const check = await client.check(manifestYaml);
if (check.would_block) {
  console.error("Deployment would be blocked:");
  check.blocking_constraints.forEach((c) =>
    console.error(`  ${c.name}: ${c.remediation?.summary}`)
  );
}
if (check.missing_prerequisites.length > 0) {
  console.warn("Missing prerequisites:");
  check.missing_prerequisites.forEach((mp) =>
    console.warn(`  ${mp.expected_kind}: ${mp.reason}`)
  );
}
```

---

## SSE Event Streaming

Subscribe to real-time constraint changes via the `/sse` endpoint:

```python
import httpx

with httpx.stream("GET", "http://localhost:8090/sse") as response:
    for line in response.iter_lines():
        if line.startswith("data: "):
            import json
            event = json.loads(line[6:])
            print(f"Constraint {event['type']}: {event['data']['constraintName']} "
                  f"in {event['data']['namespace']}")
```

Events are broadcast when constraints are added, updated, or removed. Each event includes:

```json
{
  "type": "constraint_change",
  "data": {
    "type": "added",
    "constraintUID": "abc123",
    "constraintName": "restrict-egress",
    "namespace": "production",
    "constraintType": "NetworkEgress",
    "severity": "Critical"
  }
}
```

---

## In-Cluster Agent

For agents running inside the cluster, connect directly to the Potoo service using Kubernetes ServiceAccount authentication.

### ServiceAccount Setup

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-agent
  namespace: my-app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: my-agent-potoo
subjects:
  - kind: ServiceAccount
    name: my-agent
    namespace: my-app
roleRef:
  kind: ClusterRole
  name: potoo-mcp-client
  apiGroup: rbac.authorization.k8s.io
```

### Connecting from a Pod

```python
import httpx

# Read the ServiceAccount token
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    token = f.read()

# Connect directly to the Potoo service (no port-forward needed)
client = PotooClient(
    base_url="http://potoo-controller.potoo-system.svc:8090",
    token=token
)

# Query constraints in the agent's own namespace
result = client.query(namespace="my-app")
```

---

## CI/CD Integration

Use Potoo's pre-check in CI pipelines to catch constraint issues before deployment:

```yaml
# GitHub Actions example
- name: Pre-check deployment
  run: |
    RESULT=$(curl -s -X POST http://potoo:8090/tools/potoo_check \
      -H 'Content-Type: application/json' \
      -d "{\"manifest\": $(cat deploy/manifest.yaml | jq -Rs .)}")

    WOULD_BLOCK=$(echo "$RESULT" | jq -r '.would_block')
    if [ "$WOULD_BLOCK" = "true" ]; then
      echo "Deployment would be blocked:"
      echo "$RESULT" | jq '.blocking_constraints[].name'
      exit 1
    fi

    MISSING=$(echo "$RESULT" | jq '.missing_prerequisites | length')
    if [ "$MISSING" -gt 0 ]; then
      echo "Warning: missing prerequisites:"
      echo "$RESULT" | jq -r '.missing_prerequisites[] | "  \(.expected_kind): \(.reason)"'
    fi
```

---

## Troubleshooting

### Connection Refused

```bash
# Check MCP is enabled
kubectl get deployment -n potoo-system potoo-controller -o yaml | grep -A5 mcp

# Check pod is running
kubectl get pods -n potoo-system -l app=potoo-controller

# Check service exists
kubectl get svc -n potoo-system potoo-controller

# Test connectivity from inside the cluster
kubectl exec -it -n potoo-system deployment/potoo-controller -- \
  curl -s http://localhost:8090/resources/health
```

### Authentication Errors

```bash
# Verify your ServiceAccount has the right role
kubectl auth can-i get constraintreports --as=system:serviceaccount:my-app:my-agent

# Test with a token
TOKEN=$(kubectl create token my-agent -n my-app)
curl -s http://localhost:8090/resources/health \
  -H "Authorization: Bearer $TOKEN"
```

### Empty Results

```bash
# Verify constraints exist in the cluster
kubectl get constraintreports -A

# Check the indexer has data
curl -s http://localhost:8090/resources/capabilities | jq '.totalConstraints'

# Check controller logs for errors
kubectl logs -n potoo-system -l app=potoo-controller | grep -i mcp
```

---

## Best Practices

### For Agent Developers

1. **Start with tool discovery**: Call `GET /mcp/tools` to see available tools and their schemas
2. **Handle confidence levels**: Don't present low-confidence matches with certainty
3. **Show remediation steps**: Always surface remediation when available — it's the most actionable part
4. **Use pre-check proactively**: Call `potoo_check` before deploying to catch issues early
5. **Check `missing_prerequisites`**: Pre-check results include missing companion resources, not just blocking constraints
6. **Respect privacy**: Don't cache or log cross-namespace constraint details

### For Platform Teams

1. **Enable MCP in production**: Set `mcp.enabled: true` in your Helm values
2. **Configure authentication**: Use `kubernetes-sa` for in-cluster agents, `bearer-token` for external
3. **Set remediation contacts**: Fill in `privacy.remediationContact` so developers know who to ask
4. **Monitor usage**: Check MCP request metrics via the Prometheus endpoint

### Security Considerations

1. MCP respects RBAC — agents see only what their ServiceAccount allows
2. Cross-namespace constraint names are redacted by default
3. Sensitive policy details (Rego source, webhook URLs) are never exposed
4. Use network policies to restrict which pods can reach the MCP port
