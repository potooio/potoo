---
layout: default
title: remediate
parent: CLI (potoo)
nav_order: 4
---

# potoo remediate
{: .no_toc }

Get detailed remediation steps for a specific constraint.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Synopsis

```bash
potoo remediate -n <namespace> <constraint-name> [flags]
```

---

## Description

The `remediate` command provides detailed, structured remediation steps for a specific constraint. Unlike `explain` which aggregates remediation from multiple constraints, this command focuses on a single constraint with full detail.

---

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--namespace` | `-n` | Yes | Namespace where the constraint is active |
| `--output` | `-o` | No | Output format: table, json, yaml |

---

## Remediation Step Types

| Type | Description | Fields |
|------|-------------|--------|
| `manual` | Human action required | description, contact |
| `kubectl` | kubectl command to run | description, command |
| `annotation` | Add annotation to workload | description, patch |
| `yaml_patch` | Modify manifest YAML | description, template |
| `link` | Documentation reference | description, url |

---

## Privilege Levels

Each step indicates the required privilege:

| Level | Who Can Execute |
|-------|-----------------|
| `developer` | Any developer in the namespace |
| `namespace-admin` | Namespace admin (can modify resources) |
| `cluster-admin` | Platform team (can modify policies) |

---

## Examples

### Basic Remediation

```bash
potoo remediate -n my-namespace restrict-egress
```

Output:
```
Constraint: restrict-egress
Type:       NetworkEgress
Severity:   Critical
Effect:     deny

Summary: Request network policy exception to allow egress

Steps:
  1. [manual] (developer)
     Contact platform team to request egress exception
     Contact: platform-team@company.com

  2. [kubectl] (namespace-admin)
     Add exception annotation to workload
     Command: kubectl annotate deployment my-app potoo.io/egress-exception=requested

  3. [link]
     Review network policy documentation
     URL: https://wiki.company.com/network-policies
```

### Remediation for Admission Policy

```bash
potoo remediate -n my-namespace require-limits
```

Output:
```
Constraint: require-limits
Type:       Admission
Severity:   Critical
Effect:     deny

Summary: Add resource limits to container specs

Steps:
  1. [yaml_patch] (developer)
     Add resources section to each container in your deployment
     Template:
       resources:
         limits:
           cpu: "500m"
           memory: "256Mi"
         requests:
           cpu: "100m"
           memory: "128Mi"

  2. [link]
     See resource management best practices
     URL: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
```

### Remediation for Resource Quota

```bash
potoo remediate -n my-namespace compute-quota
```

Output:
```
Constraint: compute-quota
Type:       ResourceLimit
Severity:   Warning
Effect:     limit

Summary: Manage resource usage within quota limits

Steps:
  1. [kubectl] (developer)
     Check current quota usage
     Command: kubectl get resourcequota compute-quota -n my-namespace -o yaml

  2. [manual] (namespace-admin)
     Request quota increase if needed
     Contact: platform-team@company.com

  3. [link]
     Quota request process
     URL: https://wiki.company.com/quota-requests
```

### JSON Output

```bash
potoo remediate -n my-namespace restrict-egress -o json
```

Output:
```json
{
  "constraint": {
    "name": "restrict-egress",
    "type": "NetworkEgress",
    "severity": "Critical",
    "effect": "deny",
    "source": "NetworkPolicy"
  },
  "summary": "Request network policy exception to allow egress",
  "steps": [
    {
      "type": "manual",
      "description": "Contact platform team to request egress exception",
      "contact": "platform-team@company.com",
      "requires_privilege": "developer",
      "automated": false
    },
    {
      "type": "kubectl",
      "description": "Add exception annotation to workload",
      "command": "kubectl annotate deployment my-app potoo.io/egress-exception=requested",
      "requires_privilege": "namespace-admin",
      "automated": true
    },
    {
      "type": "link",
      "description": "Review network policy documentation",
      "url": "https://wiki.company.com/network-policies",
      "requires_privilege": "",
      "automated": false
    }
  ]
}
```

---

## Automated Steps

Steps with `type: kubectl` or `type: annotation` are marked as `automated: true` in JSON output. These can be executed programmatically.

```bash
# Extract and run kubectl commands
potoo remediate -n my-namespace restrict-egress -o json | \
  jq -r '.steps[] | select(.automated == true) | .command' | \
  while read cmd; do
    echo "Running: $cmd"
    eval "$cmd"
  done
```

---

## Response Schema

### RemediateResult

| Field | Type | Description |
|-------|------|-------------|
| `constraint` | ConstraintInfo | The constraint details |
| `summary` | string | One-line remediation summary |
| `steps` | RemediationStep[] | Ordered list of remediation steps |

### RemediationStep

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | manual, kubectl, annotation, yaml_patch, link |
| `description` | string | Human-readable explanation |
| `command` | string | kubectl command (when type=kubectl) |
| `patch` | string | Annotation patch (when type=annotation) |
| `template` | string | YAML template (when type=yaml_patch) |
| `url` | string | Documentation URL (when type=link) |
| `contact` | string | Contact info (when type=manual) |
| `requires_privilege` | string | developer, namespace-admin, cluster-admin |
| `automated` | boolean | True if step can be executed programmatically |

---

## Template Placeholders

YAML templates may contain placeholders:

| Placeholder | Replaced With |
|-------------|---------------|
| `{workload_name}` | Name from context |
| `{namespace}` | Namespace from context |

Example template:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {workload_name}
  namespace: {namespace}
```

---

## Error Handling

If the constraint is not found:

```bash
potoo remediate -n my-namespace nonexistent-constraint
```

Output:
```
Error: constraint "nonexistent-constraint" not found in namespace "my-namespace"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (constraint not found, API error, etc.) |

---

## See Also

- [explain](../explain/) - Get remediation for matching constraints from an error
- [query](../query/) - List all constraints to find constraint names
