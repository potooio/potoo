// Package webhookconfig provides a constraint adapter for
// admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration resources.
//
// # Parsing
//
// Handles TWO GVRs:
//   - {"admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations"}
//   - {"admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations"}
//
// Iterates `webhooks[]`. For each webhook entry, produces one Constraint:
//   - ConstraintType: Admission
//   - Severity: Warning if failurePolicy=Fail, Info if failurePolicy=Ignore
//   - Summary: "Validating webhook 'NAME' intercepts CREATE,UPDATE on pods, deployments"
//   - Details: {"operations": [...], "resources": [...], "failurePolicy": "Fail|Ignore"}
//   - ResourceTargets: parsed from rules[].apiGroups and rules[].resources
//   - NamespaceSelector: parsed from webhooks[].namespaceSelector if present
//
// # Filtering
//
// Skip webhook entries where:
//   - name contains "potoo" (our own webhooks)
//   - clientConfig.service.name contains "potoo"
package webhookconfig
