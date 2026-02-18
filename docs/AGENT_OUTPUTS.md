# Agent-Consumable Outputs

## The Problem

Potoo discovers constraints and produces notifications. But its outputs need to be useful not just to humans reading `kubectl describe` — they need to be programmatically consumable by AI agents operating in the cluster. An SRE copilot debugging a failed deployment, an incident response agent correlating alerts, or a developer's AI assistant trying to unblock them should all be able to query Potoo and get structured, actionable data.

This document defines how every Potoo output is designed for machine consumption.

## Design Principles

1. **Every output has a structured form.** No output exists only as a human-readable string. There is always a machine-parseable representation alongside.

2. **Outputs are self-describing.** An agent encountering a ConstraintReport for the first time should be able to understand it without external documentation, through field names, embedded descriptions, and JSON Schema.

3. **Remediation is actionable data, not prose.** Instead of "contact platform-team@company.com", provide structured remediation steps that an agent could execute or present as options.

4. **Query interfaces exist at multiple levels.** Agents may interact via MCP protocol, kubectl plugin, CRD status fields, Kubernetes Events, or Prometheus metrics. Each level serves a different agent architecture.

---

## 1. MCP Server (Model Context Protocol)

Potoo exposes an MCP server that AI agents can connect to for real-time constraint querying.

### Why MCP

MCP is emerging as the standard protocol for giving AI agents access to external tools and data sources. By exposing an MCP server, any MCP-compatible agent (Claude, Copilot, custom agents) can directly query Potoo without parsing CRDs or kubectl output.

### MCP Tools Exposed

```
potoo_query
  Query constraints affecting a specific namespace or workload.
  Parameters:
    namespace: string (required)
    workload_name: string (optional — filter to specific workload)
    workload_labels: map[string]string (optional — match by labels)
    constraint_type: string (optional — filter: NetworkIngress, NetworkEgress, Admission, ResourceLimit, etc.)
    severity: string (optional — filter: Critical, Warning, Info)
    include_remediation: bool (default true)
  Returns:
    constraints: []ConstraintResult

potoo_explain
  Given a specific error message or event, explain which constraint caused it and how to fix it.
  Parameters:
    error_message: string (the error text from a failed kubectl apply, pod event, etc.)
    namespace: string (required)
    workload_name: string (optional)
  Returns:
    explanation: string (natural-language explanation)
    matching_constraints: []ConstraintResult
    remediation_steps: []RemediationStep

potoo_check
  Pre-check whether a workload would be blocked before deploying it.
  Parameters:
    manifest: string (YAML of the resource to check)
  Returns:
    would_block: bool
    blocking_constraints: []ConstraintResult
    missing_prerequisites: []MissingResource
    warnings: []string

potoo_list_namespaces
  List all namespaces with their constraint summary (count by severity).
  Returns:
    namespaces: []NamespaceSummary

potoo_remediation
  Get detailed remediation steps for a specific constraint.
  Parameters:
    constraint_name: string
    namespace: string
  Returns:
    steps: []RemediationStep
```

### MCP Resources Exposed

```
potoo://reports/{namespace}
  The full ConstraintReport for a namespace, as structured JSON.

potoo://constraints/{namespace}/{name}
  A specific constraint's full details.

potoo://health
  Sentinel's operational health: watched GVRs, adapter status, last scan time.
```

### Result Types

```json
{
  "ConstraintResult": {
    "name": "restrict-egress",
    "namespace": "team-alpha",
    "constraint_type": "NetworkEgress",
    "severity": "Warning",
    "source_kind": "NetworkPolicy",
    "source_api_version": "networking.k8s.io/v1",
    "effect": "Restricts egress to ports 443, 8443",
    "affected_workloads": ["api-server", "web-frontend"],
    "remediation": {
      "summary": "Your workload's egress traffic is restricted by a network policy.",
      "steps": [
        {
          "type": "manual",
          "description": "Request a network policy exception from the platform team",
          "contact": "platform-team@company.com"
        },
        {
          "type": "kubectl",
          "description": "View the full policy",
          "command": "kubectl get networkpolicy restrict-egress -n team-alpha -o yaml"
        },
        {
          "type": "annotation",
          "description": "Mark your workload as requiring this egress access",
          "patch": "kubectl annotate deployment api-server potoo.io/egress-exception-requested=true"
        }
      ]
    },
    "detail_level": "summary",
    "last_observed": "2025-03-15T14:30:00Z"
  }
}
```

```json
{
  "RemediationStep": {
    "type": "manual | kubectl | annotation | yaml_patch | link",
    "description": "Human-readable description of this step",
    "command": "kubectl command to run (if type=kubectl)",
    "patch": "kubectl patch command (if type=annotation or yaml_patch)",
    "url": "link to documentation or runbook (if type=link)",
    "requires_privilege": "cluster-admin | namespace-admin | developer",
    "automated": false
  }
}
```

```json
{
  "MissingResource": {
    "expected_kind": "ServiceMonitor",
    "expected_api_version": "monitoring.coreos.com/v1",
    "reason": "Workload has port named 'metrics' but no ServiceMonitor targets it",
    "severity": "Warning",
    "remediation": {
      "type": "yaml_patch",
      "description": "Create a ServiceMonitor for this workload",
      "template": "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  name: {workload_name}-monitor\n  namespace: {namespace}\nspec:\n  selector:\n    matchLabels:\n      app: {workload_name}\n  endpoints:\n  - port: metrics"
    }
  }
}
```

### Deployment

The MCP server runs as a sidecar or additional port on the controller deployment. Configuration:

```yaml
mcp:
  enabled: true
  port: 8090
  # Transport: stdio (for local agents) or sse (for remote agents)
  transport: sse
  # Privacy: MCP responses respect the same NotificationPolicy scoping
  # The MCP client's identity determines detail level.
  authentication:
    # How to identify the calling agent's privilege level
    method: "bearer-token"  # or "kubernetes-sa" for in-cluster agents
```

---

## 2. Structured Kubernetes Events

Standard Kubernetes Events are free-text strings. Potoo adds **structured annotations** to every Event it creates, making them machine-parseable.

### Event Format

```yaml
apiVersion: v1
kind: Event
metadata:
  name: api-server.potoo.12345
  namespace: team-alpha
  annotations:
    # Machine-readable structured data (JSON)
    potoo.io/constraint-type: "NetworkEgress"
    potoo.io/constraint-name: "restrict-egress"
    potoo.io/constraint-namespace: "team-alpha"
    potoo.io/source-gvr: "networking.k8s.io/v1/networkpolicies"
    potoo.io/severity: "Warning"
    potoo.io/effect: "restrict"
    potoo.io/detail-level: "summary"
    potoo.io/remediation-type: "manual"
    potoo.io/remediation-contact: "platform-team@company.com"
    # JSON blob with full structured data for agents
    potoo.io/structured-data: |
      {"constraint_type":"NetworkEgress","severity":"Warning",
       "source_gvr":"networking.k8s.io/v1/networkpolicies",
       "affected_ports":[443,8443],"remediation_steps":[...]}
  labels:
    # Enables efficient filtering
    potoo.io/managed-by: "potoo"
    potoo.io/severity: "warning"
    potoo.io/constraint-type: "network-egress"
involvedObject:
  apiVersion: apps/v1
  kind: Deployment
  name: api-server
  namespace: team-alpha
reason: ConstraintBlocking
type: Warning
message: "Network egress from your workload is restricted. Contact platform-team@company.com."
```

### Why This Matters for Agents

An agent can now:
```bash
# Find all potoo events for a namespace
kubectl get events -n team-alpha -l potoo.io/managed-by=potoo -o json

# Filter by severity
kubectl get events -n team-alpha -l potoo.io/severity=critical -o json

# Filter by constraint type
kubectl get events -n team-alpha -l potoo.io/constraint-type=network-egress -o json

# Parse the structured data annotation for full machine-readable details
kubectl get events -n team-alpha -l potoo.io/managed-by=potoo \
  -o jsonpath='{.items[*].metadata.annotations.potoo\.io/structured-data}'
```

---

## 3. Enhanced ConstraintReport CRD

The ConstraintReport CRD is redesigned with agent consumption as a first-class concern.

### Key Changes from Original Design

1. **`status.machineReadable`** — a structured section specifically for programmatic access, separate from the human-readable entries.

2. **Remediation as structured data** — not strings, but typed steps with commands and templates.

3. **Self-describing severity** — thresholds are embedded in the report so agents know what "Warning" means for this specific constraint.

4. **Cross-references** — each entry includes the GVR and name of the source constraint object, so agents can fetch the full policy if needed (subject to RBAC).

### Enhanced ConstraintReport Schema

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintReport
metadata:
  name: team-alpha
  namespace: team-alpha
status:
  # Summary counters (unchanged)
  constraintCount: 5
  criticalCount: 1
  warningCount: 2
  infoCount: 2
  lastUpdated: "2025-03-15T14:30:00Z"

  # Human-readable entries (unchanged — for kubectl display)
  constraints:
    - name: restrict-egress
      type: NetworkEgress
      severity: Warning
      message: "Egress restricted to ports 443, 8443"
      source: networking.k8s.io/v1/networkpolicies
      affectedWorkloads: ["api-server"]
      lastSeen: "2025-03-15T14:30:00Z"

  # NEW: Machine-readable section for agents
  machineReadable:
    schemaVersion: "1"
    generatedAt: "2025-03-15T14:30:00Z"
    detailLevel: "summary"  # what level this report was rendered at
    constraints:
      - uid: "abc-123-def"
        name: "restrict-egress"
        constraintType: "NetworkEgress"
        severity: "Warning"
        effect: "restrict"
        sourceRef:
          apiVersion: "networking.k8s.io/v1"
          kind: "NetworkPolicy"
          name: "restrict-egress"
          namespace: "team-alpha"
        affectedWorkloads:
          - kind: "Deployment"
            name: "api-server"
            matchReason: "podSelector matches labels {app: api-server}"
        remediation:
          steps:
            - type: "kubectl"
              description: "View the network policy"
              command: "kubectl get networkpolicy restrict-egress -n team-alpha -o yaml"
              requiresPrivilege: "developer"
            - type: "manual"
              description: "Request an egress exception"
              contact: "platform-team@company.com"
              requiresPrivilege: "developer"
          templates: []
        tags:
          - "network"
          - "egress"
          - "port-restriction"

      - uid: "xyz-789"
        name: "team-alpha-quota"
        constraintType: "ResourceLimit"
        severity: "Warning"
        effect: "limit"
        sourceRef:
          apiVersion: "v1"
          kind: "ResourceQuota"
          name: "team-alpha-quota"
          namespace: "team-alpha"
        metrics:
          cpu:
            hard: "4"
            used: "3.2"
            unit: "cores"
            percentUsed: 80
          memory:
            hard: "8Gi"
            used: "6.1Gi"
            unit: "bytes"
            percentUsed: 76
        remediation:
          steps:
            - type: "kubectl"
              description: "Check current quota usage"
              command: "kubectl describe resourcequota team-alpha-quota -n team-alpha"
              requiresPrivilege: "developer"
            - type: "manual"
              description: "Request quota increase"
              contact: "platform-team@company.com"
              requiresPrivilege: "namespace-admin"
        tags:
          - "resources"
          - "quota"
          - "cpu"
          - "memory"

    # Proactive: missing resources detected
    missingResources:
      - expectedKind: "ServiceMonitor"
        expectedAPIVersion: "monitoring.coreos.com/v1"
        reason: "Workload api-server has port named 'metrics' but no ServiceMonitor targets it"
        severity: "Warning"
        forWorkload:
          kind: "Deployment"
          name: "api-server"
        remediation:
          steps:
            - type: "yaml_patch"
              description: "Create a ServiceMonitor"
              requiresPrivilege: "developer"
              template: |
                apiVersion: monitoring.coreos.com/v1
                kind: ServiceMonitor
                metadata:
                  name: api-server-monitor
                  namespace: team-alpha
                spec:
                  selector:
                    matchLabels:
                      app: api-server
                  endpoints:
                  - port: metrics

    # Summary tags for agent filtering
    tags: ["network", "egress", "resources", "quota", "monitoring"]
```

---

## 4. Workload Annotations

Potoo annotates affected workloads directly so agents inspecting a Deployment/Pod can immediately see constraint status without querying a separate CRD.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: team-alpha
  annotations:
    # Summary annotation (always present)
    potoo.io/status: "2 constraints (1 warning, 1 info)"
    potoo.io/last-evaluated: "2025-03-15T14:30:00Z"
    
    # Structured constraint list (JSON, for agents)
    potoo.io/constraints: |
      [
        {"type":"NetworkEgress","severity":"Warning","name":"restrict-egress","source":"NetworkPolicy"},
        {"type":"ResourceLimit","severity":"Info","name":"team-alpha-quota","source":"ResourceQuota"}
      ]
    
    # Quick severity indicator (for filtering)
    potoo.io/max-severity: "warning"
    
    # Count by severity
    potoo.io/critical-count: "0"
    potoo.io/warning-count: "1"
    potoo.io/info-count: "1"
```

This means an agent doing `kubectl get deployment api-server -o json` gets constraint context immediately — no second query needed.

---

## 5. Prometheus Metrics (Agent-Queryable)

Metrics are labeled for agent queries, not just dashboarding.

```
# Per-namespace constraint counts — agent can query "which namespaces are most constrained?"
potoo_constraints_total{namespace="team-alpha", type="NetworkEgress", severity="warning"} 1

# Per-workload constraint counts — agent can query "is this specific workload blocked?"
potoo_workload_constraints{namespace="team-alpha", workload="api-server", workload_kind="Deployment", severity="warning"} 1

# Quota utilization — agent can query "which namespaces are near quota?"
potoo_quota_utilization_percent{namespace="team-alpha", resource="cpu"} 80
potoo_quota_utilization_percent{namespace="team-alpha", resource="memory"} 76

# Missing resources — agent can query "which workloads are missing something?"
potoo_missing_resources_total{namespace="team-alpha", expected_kind="ServiceMonitor", workload="api-server"} 1

# Active traffic drops (from Hubble) — agent can correlate with alerts
potoo_traffic_drops_total{namespace="team-alpha", source_workload="api-server", destination_port="9090"} 47

# Constraint freshness — agent can check if data is stale
potoo_last_scan_timestamp_seconds 1710512400
potoo_report_age_seconds{namespace="team-alpha"} 30

# Webhook notification delivery — agent can check notification pipeline health
potoo_webhook_send_total{status="success"} 42
potoo_webhook_send_total{status="error"} 1
potoo_webhook_send_total{status="retry"} 3
potoo_webhook_send_total{status="dropped"} 0
potoo_webhook_send_duration_seconds_bucket{status="success",le="0.5"} 38
```

---

## 6. kubectl Plugin (Structured Output)

A `kubectl-sentinel` plugin provides structured JSON output for agents that interact via CLI.

```bash
# JSON output for agents
kubectl sentinel query -n team-alpha -o json
kubectl sentinel explain "failed to create pod: webhook denied" -n team-alpha -o json
kubectl sentinel check -f deployment.yaml -o json
kubectl sentinel remediate restrict-egress -n team-alpha -o json --dry-run

# Human output (default)
kubectl sentinel query -n team-alpha
kubectl sentinel explain "failed to create pod: webhook denied" -n team-alpha
```

The `-o json` output matches the MCP tool response schemas exactly, so agents can use either interface interchangeably.

---

## 7. OpenAPI Discovery

The controller serves an OpenAPI spec at `/openapi/v3` describing all queryable endpoints, CRD schemas, and MCP tool schemas. Agents discovering Potoo for the first time can read this to understand what queries are available.

```
GET /openapi/v3          → Full OpenAPI spec
GET /api/v1/health       → Operational health
GET /api/v1/capabilities → List of enabled adapters, MCP tools, watched GVRs
```

The `/api/v1/capabilities` endpoint is particularly important — it tells an agent what Potoo can and can't do in this specific cluster:

```json
{
  "adapters": {
    "networkpolicy": {"enabled": true, "watchedResources": 12},
    "cilium": {"enabled": true, "watchedResources": 5},
    "gatekeeper": {"enabled": false, "reason": "CRDs not installed"},
    "kyverno": {"enabled": true, "watchedResources": 8}
  },
  "hubble": {"enabled": true, "connected": true},
  "mcpServer": {"enabled": true, "port": 8090, "transport": "sse"},
  "totalConstraintsIndexed": 47,
  "namespacesWithConstraints": 12,
  "lastFullScan": "2025-03-15T14:25:00Z"
}
```

---

## JSON Naming Convention

Potoo intentionally uses different JSON field naming conventions across its interfaces:

| Interface | Convention | Reason |
|-----------|-----------|--------|
| CRD status fields | camelCase (`constraintType`, `percentUsed`) | Kubernetes API convention; all CRD fields use camelCase per k8s standards |
| HTTP API (`/api/v1/*`) | camelCase (`constraintTypes`, `lastScanTime`) | Same as CRDs; serves internal Kubernetes consumers (webhook, dashboards) |
| MCP Server | snake_case (`constraint_type`, `percent_used`) | JSON API convention; AI agents and external tools expect snake_case |
| kubectl plugin (`-o json`) | snake_case (`constraint_type`, `source_kind`) | Matches MCP response schema for consistent agent consumption |

This split is a deliberate design choice:

- **CRDs and HTTP API** follow the Kubernetes ecosystem convention. Tools like `kubectl`, Argo, and Kubernetes dashboards expect camelCase in CRD specs and status fields.
- **MCP and CLI JSON output** follow the JSON API / Python ecosystem convention. AI agents, Python scripts, and modern API consumers expect snake_case.

The `internal/mcp/types.go` types define the MCP wire format with explicit `json:"snake_case"` tags, while `api/v1alpha1/types.go` CRD types use `json:"camelCase"` tags. The two never share serialization paths — they are converted through `ToConstraintResult()` in the MCP layer.

---

## Privacy Scoping for Agent Outputs

All agent-facing outputs respect the same NotificationPolicy privacy model as human notifications. The detail level is determined by:

1. **MCP**: The bearer token or Kubernetes ServiceAccount identity of the calling agent.
2. **CRD/Events**: The ConstraintReport and Events are rendered at the level appropriate for the namespace (developer-scoped by default).
3. **kubectl plugin**: Uses the caller's kubeconfig RBAC.
4. **Prometheus metrics**: Metric labels are already namespace-scoped. Cross-namespace cardinality is visible only to cluster-admin scrape targets.
5. **Workload annotations**: Always developer-scoped (summary level).

An agent running as a namespace-scoped ServiceAccount sees `summary` level. An agent running as `cluster-admin` sees `full` level. This is enforced at the output rendering layer, not per-channel.
