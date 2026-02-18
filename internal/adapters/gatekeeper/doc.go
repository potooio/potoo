// Package gatekeeper implements an adapter for OPA Gatekeeper constraints.
//
// Gatekeeper creates CRDs dynamically from ConstraintTemplates. For example,
// a ConstraintTemplate named K8sRequiredLabels creates a CRD with GVR:
// constraints.gatekeeper.sh/v1beta1/k8srequiredlabels
//
// Since the resource names are not known at compile time, this adapter registers
// with a group-level matcher (constraints.gatekeeper.sh) rather than specific GVRs.
//
// # Constraint Structure
//
// Gatekeeper constraints have this structure:
//
//	spec:
//	  enforcementAction: deny|dryrun|warn
//	  match:
//	    kinds:
//	      - apiGroups: [""]
//	        kinds: ["Pod"]
//	    namespaces: ["production"]
//	    excludedNamespaces: ["kube-system"]
//	    labelSelector: {matchLabels: {...}}
//	    namespaceSelector: {matchLabels: {...}}
//	  parameters: {...}
//
// # Severity Mapping
//
//   - enforcementAction=deny → Critical
//   - enforcementAction=warn → Warning
//   - enforcementAction=dryrun → Info
package gatekeeper
