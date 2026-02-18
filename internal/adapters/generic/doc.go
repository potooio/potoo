// Package generic provides a fallback constraint adapter for CRDs that don't
// have a dedicated adapter. It extracts as much useful information as possible
// using common Kubernetes resource patterns.
//
// # Usage
//
// The generic adapter is NOT registered to specific GVRs in the adapter registry.
// Instead, the discovery engine uses it as a fallback when no specific adapter
// matches a discovered GVR. Call Parse() directly, passing any unstructured object.
//
// # Extraction Strategy (in priority order)
//
//  1. Check metadata.annotations["potoo.io/summary"] — use as Summary
//  2. Check metadata.annotations["potoo.io/severity"] — use as Severity
//  3. Look for spec.selector or spec.podSelector → extract as WorkloadSelector
//  4. Look for spec.namespaceSelector → extract as NamespaceSelector
//  5. Look for spec.match.kinds, spec.match.namespaces → extract scope
//  6. Look for spec.rules (common pattern in policy CRDs) → count rules
//  7. Look for spec.parameters → note as "parameterized policy"
//
// # Output
//
// Always produces exactly ONE Constraint:
//   - ConstraintType: Unknown (override via annotation)
//   - Severity: Info (override via annotation)
//   - Summary: from annotation, or "{Kind} {name} in {namespace}"
//   - Details: {"discoveredFields": [...list of fields found]}
//   - RemediationHint: "This constraint was auto-discovered. Contact your platform team."
package generic
