---
layout: default
title: Troubleshooting
nav_order: 8
---

# Troubleshooting
{: .no_toc }

Common issues and how to resolve them.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Constraints Not Discovered

### Symptoms

- `kubectl get constraintreport -n <namespace>` returns empty or no report
- `potoo query -n <namespace>` shows 0 constraints
- Policy resources exist but Potoo doesn't see them

### Diagnosis

**1. Check that the controller is running:**

```bash
kubectl get pods -n potoo-system -l app=potoo-controller
```

**2. Check controller logs for adapter errors:**

```bash
kubectl logs -n potoo-system -l app=potoo-controller | grep -E "adapter|error|skip"
```

**3. Verify the CRD is installed:**

```bash
# For example, Gatekeeper constraints
kubectl get crd | grep -E 'gatekeeper|constraints'
```

**4. Check if the adapter is enabled:**

```bash
curl http://localhost:8080/api/v1/capabilities  # after port-forwarding
```

Look for the adapter in the `adapters` array. If `enabled: false` with a `reason`, that explains why.

**5. For custom CRDs, verify a ConstraintProfile exists:**

```bash
kubectl get constraintprofiles
```

If your CRD isn't covered by a built-in adapter, you need a ConstraintProfile to register it. See the [ConstraintProfile CRD reference](/docs/crds/constraintprofile.html).

### Common Causes

| Cause | Fix |
|-------|-----|
| CRD not installed | Install the policy engine CRD first |
| Adapter set to `disabled` | Set to `auto` or `enabled` in Helm values |
| RBAC missing | Ensure the controller ClusterRole has `get`, `list`, `watch` on `*/*` |
| Rescan hasn't run yet | Wait for `rescanInterval` (default 5m) or restart the controller |
| ConstraintProfile not created | Create one for custom CRDs |

---

## Events Not Appearing

### Symptoms

- No `ConstraintDiscovered` events on workloads
- `kubectl describe deployment <name>` shows no Potoo events

### Diagnosis

**1. Check that event notifications are enabled:**

```yaml
# In Helm values
notifications:
  kubernetesEvents: true
```

**2. Verify the controller can create events:**

```bash
kubectl auth can-i create events \
  --as=system:serviceaccount:potoo-system:potoo-controller \
  -n <target-namespace>
```

**3. Check rate limiting:**

```bash
kubectl logs -n potoo-system -l app=potoo-controller | grep "rate"
```

Default is 100 events/minute per namespace. High constraint churn can hit this limit.

**4. Check for deduplication:**

If `deduplication.enabled: true`, unchanged constraints won't produce new events until `suppressDuplicateMinutes` expires (default: 60).

---

## Webhook Not Working

### Symptoms

- No warnings shown during `kubectl apply`
- Webhook pods are running but not intercepting requests

### Diagnosis

**1. Check webhook registration:**

```bash
kubectl get validatingwebhookconfigurations | grep potoo
```

**2. Verify failurePolicy is Ignore:**

```bash
kubectl get validatingwebhookconfigurations potoo-webhook \
  -o jsonpath='{.webhooks[0].failurePolicy}'
```

Must be `Ignore`. If it's `Fail`, fix immediately.

**3. Check webhook pods:**

```bash
kubectl get pods -n potoo-system -l app.kubernetes.io/component=webhook
kubectl logs -n potoo-system -l app.kubernetes.io/component=webhook
```

**4. Verify the webhook can reach the controller:**

```bash
kubectl exec -n potoo-system deploy/potoo-webhook -- \
  wget -qO- http://potoo-controller.potoo-system.svc:8080/api/v1/health
```

**5. Check TLS certificate:**

```bash
# Verify the TLS secret exists
kubectl get secret -n potoo-system potoo-webhook-tls

# Check certificate expiry
kubectl get secret -n potoo-system potoo-webhook-tls \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Verify CA bundle is set
kubectl get validatingwebhookconfigurations potoo-webhook \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | wc -c
```

A non-zero value means the CA bundle is present.

### Common Causes

| Cause | Fix |
|-------|-----|
| Webhook not registered | Check Helm deployment succeeded |
| Expired TLS certificate | Restart webhook pod to trigger rotation |
| CA bundle not injected | Restart webhook pod; check cert-manager if used |
| Controller unreachable | Verify controller Service and network policies |
| Namespace excluded | Check `admissionWebhook.excludedNamespaces` |

---

## Hubble Connection Failures

### Symptoms

- `hubbleStatus.connected: false` in `/api/v1/capabilities`
- Controller logs show gRPC connection errors

### Diagnosis

**1. Check Hubble Relay is running:**

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=hubble-relay
```

**2. Verify the relay address:**

```bash
kubectl get svc -n kube-system hubble-relay
```

The default address is `hubble-relay.kube-system.svc:4245`.

**3. Check network connectivity:**

```bash
kubectl exec -n potoo-system deploy/potoo-controller -- \
  nc -zv hubble-relay.kube-system.svc 4245
```

**4. Verify Cilium has Hubble enabled:**

```bash
cilium hubble port-forward &
hubble status
```

### Common Causes

| Cause | Fix |
|-------|-----|
| Hubble not enabled in Cilium | Enable Hubble in Cilium Helm values |
| Wrong relay address | Set `hubble.relayAddress` in Potoo Helm values |
| NetworkPolicy blocking gRPC | Allow egress from potoo-system to kube-system:4245 |
| Hubble Relay not deployed | Deploy Hubble Relay (`cilium hubble enable`) |

---

## MCP Server Unreachable

### Symptoms

- AI agents can't connect to the MCP server
- Connection refused on MCP port

### Diagnosis

**1. Check MCP is enabled:**

```yaml
# In Helm values
mcp:
  enabled: true
  port: 8090
```

**2. Verify the MCP port is exposed:**

```bash
kubectl get svc -n potoo-system potoo-controller -o yaml | grep 8090
```

**3. Test connectivity:**

```bash
kubectl port-forward -n potoo-system svc/potoo-controller 8090:8090
curl http://localhost:8090/resources/health
```

**4. Check controller logs for MCP errors:**

```bash
kubectl logs -n potoo-system -l app=potoo-controller | grep "mcp"
```

### Common Causes

| Cause | Fix |
|-------|-----|
| MCP not enabled | Set `mcp.enabled: true` |
| Port not exposed in Service | Check Helm chart service configuration |
| NetworkPolicy blocking ingress | Allow ingress to potoo-controller on MCP port |
| TLS required but not configured | Configure MCP TLS or use port-forwarding |

---

## ConstraintReports Not Updating

### Symptoms

- Reports show stale data
- Constraint count doesn't match actual policies

### Diagnosis

**1. Check controller logs:**

```bash
kubectl logs -n potoo-system -l app=potoo-controller | grep "report"
```

**2. Verify the CRD exists:**

```bash
kubectl get crd constraintreports.potoo.io
```

**3. Force a rescan:**

```bash
kubectl rollout restart deployment -n potoo-system potoo-controller
```

**4. Check report reconciler settings:**

The report reconciler batches updates with a per-namespace debounce (default 10s) and a worker pool (default 3 workers). For clusters with many namespaces, consider increasing `controller.reportWorkers`.
