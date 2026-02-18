// Package kyverno implements an adapter for Kyverno policies.
//
// Kyverno policies can be cluster-scoped (ClusterPolicy) or namespace-scoped (Policy).
// Each policy can contain multiple rules, and each rule becomes a separate Constraint.
//
// # Policy Structure
//
//	spec:
//	  validationFailureAction: Enforce|Audit
//	  background: true|false
//	  rules:
//	    - name: rule-name
//	      match:
//	        any:
//	          - resources:
//	              kinds: ["Pod"]
//	              namespaces: ["default"]
//	              selector: {matchLabels: {...}}
//	      validate:
//	        message: "Validation message"
//	        pattern: {...}
//
// # Rule Types
//
//   - validate: Validates resources against patterns or CEL expressions
//   - mutate: Mutates resources
//   - generate: Generates new resources
//   - verifyImages: Verifies container image signatures
//
// # Severity Mapping
//
//   - validationFailureAction=Enforce → Critical
//   - validationFailureAction=Audit → Warning
//   - mutate/generate rules → Info (non-blocking)
package kyverno
