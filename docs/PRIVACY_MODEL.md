# Privacy Model

## Principle

Developers need enough information to unblock themselves, but not so much that they can map out other tenants' security posture. The controller sees everything; notifications reveal only what the recipient is authorized to know.

## Information Classification

### BROADCAST — Safe to Show Developers

These fields can appear in developer-facing notifications (Kubernetes Events, ConstraintReport, Slack messages to the affected namespace's team):

| Information | Example | Rationale |
|---|---|---|
| Constraint existence | "A network policy restricts egress from your namespace" | Developer needs to know *something* is blocking them |
| Constraint type | "NetworkPolicy", "AdmissionPolicy", "ResourceLimit" | Helps developer understand the category of issue |
| Effect on their workload | "Egress blocked", "Resource rejected", "Missing prerequisite" | Actionable |
| Their own workload attributes | Labels, namespace, ports they're requesting | They already know this |
| Constraint name **in their own namespace** | "my-namespace/restrict-egress" | They can `kubectl get` it anyway |
| Quota/limit values for their namespace | "CPU usage at 78% of 4 cores quota" | They can `kubectl get resourcequota` anyway |
| Generic remediation guidance | "Request a network policy exception", "Add resource limits" | Helps them self-serve |
| Platform team contact | "Contact platform-team@company.com" | Unblocks them when self-serve isn't possible |

### REDACT — Must Keep Private from Developers

These fields must NEVER appear in developer-facing notifications. They are only visible to platform admins.

| Information | Risk if Leaked |
|---|---|
| Specific port numbers from policies in **other** namespaces | Reveals infrastructure topology |
| IP ranges / CIDR blocks from other namespaces' policies | Reveals network architecture |
| Policy names from **other** namespaces | Reveals other tenants' naming conventions and security posture |
| Label selectors from other tenants' policies | Reveals workload naming and organizational structure |
| Rego/CEL policy source code | Reveals security logic |
| Webhook endpoints and configuration | Reveals internal infrastructure |
| What other workloads exist in the cluster | Multi-tenancy violation |

### ADMIN-ONLY — Full Detail for Platform Teams

Platform admins (identified by ClusterRole binding or NotificationPolicy configuration) see everything:

| Information | Example |
|---|---|
| Complete constraint details | Full policy YAML, rule specifics, port numbers |
| Cross-namespace correlation | "Policy X in namespace Y is blocking namespace Z" |
| Hubble flow data with full pod identities | Source/destination pod, namespace, port, protocol |
| Constraint impact analysis | "This policy affects 47 workloads across 12 namespaces" |
| Adapter parse errors and internal state | Debugging information |

## Implementation

### NotificationPolicy CRD

```yaml
apiVersion: potoo.io/v1alpha1
kind: NotificationPolicy
metadata:
  name: default
  namespace: potoo-system
spec:
  # What developers in their own namespace see
  developerScope:
    showConstraintType: true
    showConstraintName: "same-namespace-only"
    showAffectedPorts: false
    showSpecificCIDRs: false
    showRemediationContact: true
    contact: "platform-team@company.com"
    maxDetailLevel: "summary"    # summary | detailed | full

  # What namespace admins see (optional intermediate tier)
  namespaceAdminScope:
    showConstraintName: "same-namespace-only"
    showAffectedPorts: true
    maxDetailLevel: "detailed"

  # What platform admins see
  platformAdminScope:
    showConstraintName: "all"
    showAffectedPorts: true
    showCrossNamespaceDetails: true
    showPolicySource: true
    maxDetailLevel: "full"

  # How to determine who is a platform admin
  platformAdminIdentification:
    clusterRoles:
      - "cluster-admin"
      - "platform-admin"
    # Or by namespace annotation:
    # namespaceAnnotation: "potoo.io/admin-team"
```

### Notification Rendering

The same constraint event produces different messages per scope:

**Developer sees:**
```
⚠️ Network egress from your workload `api-server` is restricted by a
cluster network policy. Your workload cannot reach external services on
the requested port. Contact platform-team@company.com to request an exception.
```

**Namespace admin sees:**
```
⚠️ Network egress from workload `api-server` is restricted. Allowed egress
ports: [443, 8443]. The workload attempted to reach port 9090 which is not
in the allowlist. Policy source: cluster-scoped network policy.
Contact platform-team@company.com to modify the policy.
```

**Platform admin sees:**
```
⚠️ CiliumClusterwideNetworkPolicy `restrict-monitoring-egress` is blocking
egress from pod `api-server-7b4d9f` (namespace: `team-alpha`) to
`prometheus-server.monitoring.svc:9090`. Policy allows egress only to ports
[443, 8443] for pods matching label `tier=frontend`. Policy was created
2024-01-15 by user platform-ops@company.com.
```

### RBAC Enforcement

The ConstraintReport CRD is namespace-scoped. Standard Kubernetes RBAC controls who can read reports in which namespaces. The controller creates reports containing only the detail level appropriate for the namespace's configured scope.

For external channels (Slack, webhooks), the notification dispatcher checks the recipient's scope before rendering the message. Platform admin channels receive full detail; developer channels receive summary detail.

### Webhook Privacy Scoping

Generic webhook notifications use **summary-level** privacy scoping. The `EventStructuredData` payload embedded in webhook envelopes follows the same privacy rules as Kubernetes Events:

- **Constraint names** are redacted to `"redacted"` for cross-namespace constraints
- **Constraint namespace** is omitted for cross-namespace constraints
- **Source details** (name, namespace) are omitted at summary level
- **Remediation steps** redact cluster-admin commands at summary level
- **Summary text** uses generic descriptions instead of policy-specific details

This ensures webhook consumers (PagerDuty, custom dashboards, SIEM tools) receive actionable notifications without leaking cross-namespace policy information.

## Edge Cases

### Cross-Namespace Policy Impact
When a cluster-scoped policy (e.g., CiliumClusterwideNetworkPolicy) affects multiple namespaces, each namespace's ConstraintReport receives its own entry with developer-appropriate detail. The platform admin view shows the full cross-namespace impact.

### Policy Name Collisions
If a same-namespace constraint has the same name as a different-namespace constraint, the developer only sees the one in their namespace. The other is described generically as "a cluster-scoped policy."

### Hubble Flow Data
Hubble flows contain source and destination pod identities across namespaces. The notification dispatcher strips the cross-namespace pod identity before sending to developer channels. Developers see "traffic to port 9090 was dropped" not "traffic to prometheus-server-abc123 in namespace monitoring was dropped."
