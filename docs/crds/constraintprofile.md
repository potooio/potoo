---
layout: default
title: ConstraintProfile
parent: CRDs
nav_order: 2
---

# ConstraintProfile
{: .no_toc }

Configure how specific CRD types are discovered and parsed.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

ConstraintProfile is a cluster-scoped resource that configures how Potoo discovers and parses policy CRDs. Use it to:

- Register custom policy CRDs not covered by built-in adapters
- Override severity levels for specific policy types
- Disable discovery for specific CRDs
- Tune debounce intervals

**API Version:** `potoo.io/v1alpha1`

**Short Name:** `cp`

**Scope:** Cluster

---

## Usage

```bash
# List all profiles
kubectl get constraintprofiles

# View a specific profile
kubectl get cp custom-network-policy -o yaml

# Create a profile
kubectl apply -f constraintprofile.yaml
```

---

## Spec

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: my-custom-policy
spec:
  # Target resource type
  gvr:
    group: custom.example.com
    version: v1
    resource: networkrules

  # Adapter to use for parsing
  adapter: generic

  # Enable/disable watching
  enabled: true

  # Override default severity
  severity: Warning

  # Override default debounce interval
  debounceSeconds: 300
```

---

## Spec Fields

### gvr (required)

Identifies the target Kubernetes resource type:

| Field | Type | Description |
|-------|------|-------------|
| `group` | string | API group (e.g., "networking.k8s.io") |
| `version` | string | API version (e.g., "v1") |
| `resource` | string | Plural resource name (e.g., "networkpolicies") |

### adapter (required)

Name of the adapter to use for parsing:

| Value | Description |
|-------|-------------|
| `generic` | Fallback adapter for unknown CRDs |
| `networkpolicy` | Kubernetes NetworkPolicy |
| `resourcequota` | ResourceQuota/LimitRange |
| `webhook` | Webhook configurations |
| `cilium` | Cilium policies |
| `gatekeeper` | OPA Gatekeeper constraints |
| `kyverno` | Kyverno policies |
| `istio` | Istio authorization policies |

For custom CRDs, use `generic`.

### enabled

| Value | Description |
|-------|-------------|
| `true` | Watch and parse this resource type |
| `false` | Do not watch this resource type |

Default: `true`

### severity

Override the default severity for constraints from this source:

| Value | Description |
|-------|-------------|
| `Critical` | Active blocking |
| `Warning` | Approaching limits, audit mode |
| `Info` | Informational |

If not specified, the adapter determines severity based on the constraint effect.

### debounceSeconds

Override the default debounce interval for notifications:

| Value | Description |
|-------|-------------|
| `0` | Notify immediately on every change |
| `60` | Wait 60 seconds before notifying |
| `300` | Wait 5 minutes (useful for noisy CRDs) |

Default: From `requirements.debounceSeconds` in Helm values (default 120).

### fieldPaths

Configure custom field extraction paths for the `generic` adapter. Each path is a dot-delimited string that tells the generic adapter where to find specific fields in the CRD's spec.

| Field | Type | Description |
|-------|------|-------------|
| `selectorPath` | string | Path to label selector (e.g., `spec.target.workloads`) |
| `namespaceSelectorPath` | string | Path to namespace selector (e.g., `spec.scope.namespaces`) |
| `effectPath` | string | Path to the policy effect/action (e.g., `spec.action`) |
| `summaryPath` | string | Path to a human-readable summary (e.g., `spec.description`) |

All fields are optional. When unset, the generic adapter uses its default extraction behavior.

**Example:**
```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-policy
spec:
  gvr:
    group: policy.company.com
    version: v1
    resource: deploymentrestrictions
  adapter: generic
  enabled: true
  severity: Warning
  fieldPaths:
    selectorPath: "spec.target.workloads"
    namespaceSelectorPath: "spec.scope.namespaces"
    effectPath: "spec.action"
    summaryPath: "spec.description"
```

**Precedence:** When both a `fieldPaths.summaryPath` value and a `potoo.io/summary` annotation exist on the resource, the annotation takes precedence. Similarly, a `potoo.io/severity` annotation on the resource overrides the profile's `severity` setting.

---

## CRD Annotation Discovery

CRD authors can annotate their CustomResourceDefinition with `potoo.io/is-policy: "true"` to tell Potoo to automatically discover and watch instances of that CRD:

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: networkrules.security.mycompany.com
  annotations:
    potoo.io/is-policy: "true"
spec:
  # ...
```

When this annotation is present, the discovery engine automatically treats instances of this CRD as constraint-like resources. No ConstraintProfile is needed for basic discovery, though you can still create one to customize severity, field paths, or debounce settings.

This feature can be disabled via the `--check-crd-annotations=false` flag or the `discovery.checkCRDAnnotations` Helm value.

---

## Use Cases

### Register a Custom Policy CRD

Your organization has a custom network policy CRD:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-network-policy
spec:
  gvr:
    group: security.mycompany.com
    version: v1
    resource: networkrules
  adapter: generic
  enabled: true
  severity: Warning
```

### Disable Discovery for a CRD

You have Kyverno installed but don't want Potoo to watch it:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: disable-kyverno
spec:
  gvr:
    group: kyverno.io
    version: v1
    resource: clusterpolicies
  adapter: kyverno
  enabled: false
```

### Override Severity

Make ResourceQuota constraints Critical instead of Warning:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: critical-quotas
spec:
  gvr:
    group: ""
    version: v1
    resource: resourcequotas
  adapter: resourcequota
  enabled: true
  severity: Critical
```

### Configure Custom Field Extraction

Your CRD stores selectors and effects in non-standard locations:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-deployment-restrictions
spec:
  gvr:
    group: policy.internal.company.com
    version: v1
    resource: deploymentrestrictions
  adapter: generic
  enabled: true
  severity: Warning
  fieldPaths:
    selectorPath: "spec.target.workloads"
    namespaceSelectorPath: "spec.scope.namespaces"
    effectPath: "spec.action"
    summaryPath: "spec.description"
```

### Advanced Field Paths: Real-World CRD Patterns

For CRDs with deeply nested or array-based structures, field paths use dot notation. The generic adapter traverses maps at each path segment.

**Crossplane CompositeResourceDefinition:**

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: crossplane-xrd
spec:
  gvr:
    group: apiextensions.crossplane.io
    version: v1
    resource: compositeresourcedefinitions
  adapter: generic
  enabled: true
  severity: Info
  fieldPaths:
    summaryPath: "spec.names.kind"
    effectPath: "spec.claimNames.kind"
```

**cert-manager Certificate:**

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: certmanager-certificates
spec:
  gvr:
    group: cert-manager.io
    version: v1
    resource: certificates
  adapter: generic
  enabled: true
  severity: Warning
  fieldPaths:
    namespaceSelectorPath: "spec.secretName"
    summaryPath: "spec.commonName"
    effectPath: "spec.issuerRef.kind"
```

**CRD with nested array selectors:**

When a CRD stores selectors inside an array, the field path should point to the parent object containing `matchLabels`. The generic adapter handles the standard Kubernetes `matchLabels`/`matchExpressions` structure when it encounters a map at the selector path.

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: custom-access-policy
spec:
  gvr:
    group: access.company.com
    version: v1beta1
    resource: accesspolicies
  adapter: generic
  enabled: true
  severity: Critical
  fieldPaths:
    selectorPath: "spec.subjects.selector"
    effectPath: "spec.effect"
    summaryPath: "spec.description"
```

{: .note }
> Field paths that resolve to `nil` are silently skipped. The generic adapter always nil-checks each path segment, so missing or renamed fields in CRD schema changes won't cause crashes.

### Reduce Notification Noise

A CRD changes frequently but you only want occasional notifications:

```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: noisy-policy
spec:
  gvr:
    group: policy.example.com
    version: v1
    resource: noisypolicies
  adapter: generic
  enabled: true
  debounceSeconds: 600  # 10 minutes
```

---

## Built-in Profiles

Potoo includes implicit profiles for built-in adapters. You can override them by creating a ConstraintProfile with the same GVR.

| Resource | Implicit Profile |
|----------|-----------------|
| NetworkPolicy | enabled, adapter=networkpolicy |
| ResourceQuota | enabled, adapter=resourcequota |
| LimitRange | enabled, adapter=resourcequota |
| ValidatingWebhookConfiguration | enabled, adapter=webhook |
| MutatingWebhookConfiguration | enabled, adapter=webhook |
| CiliumNetworkPolicy | auto, adapter=cilium |
| CiliumClusterwideNetworkPolicy | auto, adapter=cilium |
| Gatekeeper constraints | auto, adapter=gatekeeper |
| Kyverno policies | auto, adapter=kyverno |
| Istio policies | auto, adapter=istio |

---

## Generic Adapter Behavior

When using `adapter: generic`, Potoo extracts:

| Field | Source |
|-------|--------|
| `name` | `metadata.name` |
| `namespace` | `metadata.namespace` |
| `labels` | `metadata.labels` |
| `summary` | `spec.description` (if present) |

The constraint type is set to `Unknown` and severity defaults to `Info`.

---

## Validation

The controller validates ConstraintProfiles on creation:

**Valid:**
```yaml
spec:
  gvr:
    group: example.com
    version: v1
    resource: policies
  adapter: generic
```

**Invalid (missing fields):**
```yaml
spec:
  gvr:
    group: example.com
    # version missing
    resource: policies
  adapter: generic
```

**Invalid (unknown adapter):**
```yaml
spec:
  gvr:
    group: example.com
    version: v1
    resource: policies
  adapter: nonexistent
```

---

## Lifecycle

1. **Apply Profile**: `kubectl apply -f profile.yaml`
2. **Controller Reconciles**: The ConstraintProfile controller detects the change immediately via a controller-runtime watch
3. **Informer Started**: If enabled, a dedicated informer is started for the profile's GVR
4. **Parsing Begins**: New constraints appear in reports

Deletion is also handled immediately — when a ConstraintProfile is deleted, the controller unregisters the profile and cleans up all associated constraints from the indexer.

---

## Example: Complete Custom Policy Setup

1. Your custom CRD:
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: networkrules.security.mycompany.com
spec:
  group: security.mycompany.com
  versions:
    - name: v1
      served: true
      storage: true
  scope: Namespaced
  names:
    plural: networkrules
    singular: networkrule
    kind: NetworkRule
```

2. A policy instance:
```yaml
apiVersion: security.mycompany.com/v1
kind: NetworkRule
metadata:
  name: block-external
  namespace: production
spec:
  description: "Block all external egress"
  effect: deny
  targets:
    - type: egress
      cidr: "0.0.0.0/0"
```

3. ConstraintProfile to register it:
```yaml
apiVersion: potoo.io/v1alpha1
kind: ConstraintProfile
metadata:
  name: mycompany-networkrules
spec:
  gvr:
    group: security.mycompany.com
    version: v1
    resource: networkrules
  adapter: generic
  enabled: true
  severity: Critical
```

4. Result in ConstraintReport:
```yaml
constraints:
  - name: block-external
    type: Unknown
    severity: Critical
    message: "Block all external egress"
    source: NetworkRule
```
