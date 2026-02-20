---
layout: default
title: check
parent: CLI (potoo)
nav_order: 3
---

# potoo check
{: .no_toc }

Pre-check whether a manifest would be blocked by constraints.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Synopsis

```bash
potoo check -f <manifest-file> [flags]
```

---

## Description

The `check` command analyzes a Kubernetes manifest and predicts whether it would be blocked by existing constraints. This enables pre-flight validation before deployment.

The command:
1. Parses the manifest to extract namespace, labels, and resource type
2. Queries constraints in the target namespace
3. Evaluates which constraints would block or warn

---

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--filename` | `-f` | Yes | Path to the manifest file (YAML) |
| `--output` | `-o` | No | Output format: table, json, yaml |

---

## What Gets Checked

| Constraint Type | Check Behavior |
|-----------------|----------------|
| Admission (Critical) | Marked as blocking |
| ResourceLimit | Warning if no limits specified |
| NetworkEgress | Warning about restricted ports |
| NetworkIngress | Warning about restricted ingress |

---

## Examples

### Basic Check

```bash
potoo check -f deployment.yaml
```

Output (no issues):
```
Manifest: Deployment/my-app in namespace my-namespace

Would Block: false
Warnings: none
```

Output (blocking constraint):
```
Manifest: Deployment/my-app in namespace my-namespace

Would Block: true

Blocking Constraints:
  NAME            TYPE       SEVERITY   MESSAGE
  require-limits  Admission  Critical   Pods must have resource limits

Warnings:
  - restrict-egress: Egress limited to ports 443, 8443
```

### Deployment Without Resource Limits

Given this manifest:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: app
          image: nginx
          # No resources specified
```

```bash
potoo check -f deployment.yaml
```

Output:
```
Manifest: Deployment/my-app in namespace production

Would Block: true

Blocking Constraints:
  NAME            TYPE       SEVERITY   MESSAGE
  require-limits  Admission  Critical   Container resources are required

Warnings:
  - compute-quota: ResourceQuota applies. Current usage at 75%.
```

### JSON Output

```bash
potoo check -f deployment.yaml -o json
```

Output:
```json
{
  "would_block": true,
  "blocking_constraints": [
    {
      "name": "require-limits",
      "constraint_type": "Admission",
      "severity": "Critical",
      "effect": "deny",
      "source_kind": "ValidatingWebhookConfiguration",
      "remediation": {
        "summary": "Add resource limits to container spec",
        "steps": [
          {
            "type": "yaml_patch",
            "description": "Add resources section to container",
            "template": "resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"256Mi\""
          }
        ]
      }
    }
  ],
  "missing_prerequisites": [],
  "warnings": [
    "restrict-egress: Egress limited to ports 443, 8443"
  ],
  "manifest": {
    "kind": "Deployment",
    "name": "my-app",
    "namespace": "production"
  }
}
```

### Check with Missing Prerequisites

If the manifest requires companion resources (like a ServiceMonitor for Prometheus):

```bash
potoo check -f deployment.yaml -o json
```

Output:
```json
{
  "would_block": false,
  "blocking_constraints": [],
  "missing_prerequisites": [
    {
      "expected_kind": "ServiceMonitor",
      "expected_api_version": "monitoring.coreos.com/v1",
      "reason": "Workload has prometheus.io/scrape annotation but no ServiceMonitor",
      "severity": "Warning",
      "for_workload": "production/Deployment/my-app",
      "remediation": {
        "summary": "Create ServiceMonitor for workload",
        "steps": [
          {
            "type": "yaml_patch",
            "description": "Create ServiceMonitor",
            "template": "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  name: {workload_name}\n  namespace: {namespace}"
          }
        ]
      }
    }
  ],
  "warnings": []
}
```

### Default Namespace Handling

If the manifest doesn't specify a namespace, `default` is assumed:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  # No namespace specified
spec:
  containers:
    - name: app
      image: nginx
```

```bash
potoo check -f pod.yaml
```

Output:
```
Manifest: Pod/my-pod in namespace default

Would Block: false
Warnings: none
```

---

## Response Schema

### CheckResult

| Field | Type | Description |
|-------|------|-------------|
| `would_block` | boolean | True if any Critical admission constraint would block |
| `blocking_constraints` | ConstraintInfo[] | Constraints that would block deployment |
| `missing_prerequisites` | MissingResource[] | Required resources that don't exist |
| `warnings` | string[] | Non-blocking warnings |
| `manifest` | ManifestInfo | Parsed manifest metadata |

### ManifestInfo

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Kubernetes kind |
| `name` | string | Resource name |
| `namespace` | string | Target namespace |

### MissingResource

| Field | Type | Description |
|-------|------|-------------|
| `expected_kind` | string | Kubernetes kind that should exist |
| `expected_api_version` | string | API version |
| `reason` | string | Why this resource is expected |
| `severity` | string | Warning or Info |
| `for_workload` | string | Which workload needs it |
| `remediation` | RemediationResult | Steps to create the resource |

---

## Use Cases

### CI/CD Pre-Deployment Check

```bash
#!/bin/bash
# In CI pipeline

potoo check -f deployment.yaml -o json > check-result.json

if jq -e '.would_block == true' check-result.json > /dev/null; then
  echo "Deployment would be blocked by policy"
  jq '.blocking_constraints[].name' check-result.json
  exit 1
fi

kubectl apply -f deployment.yaml
```

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

for file in $(git diff --cached --name-only | grep -E '\.ya?ml$'); do
  if potoo check -f "$file" -o json | jq -e '.would_block' > /dev/null 2>&1; then
    result=$(potoo check -f "$file" -o json)
    if echo "$result" | jq -e '.would_block == true' > /dev/null; then
      echo "Warning: $file may be blocked by policy"
      echo "$result" | jq '.blocking_constraints[].name'
    fi
  fi
done
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (check completed, regardless of result) |
| 1 | Error (file not found, invalid YAML, API error) |

Note: The exit code does not indicate whether the manifest would be blocked. Use `-o json` and parse the `would_block` field for scripting.

---

## See Also

- [query](query.html) - List all constraints
- [explain](explain.html) - Explain errors after deployment fails
