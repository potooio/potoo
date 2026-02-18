// Package limitrange provides a constraint adapter for core/v1 LimitRange objects.
//
// # Parsing
//
// Handles GVR: {"", "v1", "limitranges"}
//
// Reads `spec.limits[]`. Each entry has:
//   - type: "Container", "Pod", or "PersistentVolumeClaim"
//   - default: resource quantities applied if not specified
//   - defaultRequest: default request quantities
//   - max: upper bound
//   - min: lower bound
//   - maxLimitRequestRatio: max ratio of limit/request
//
// Produces ONE Constraint per LimitRange entry (not per LimitRange object):
//   - ConstraintType: ResourceLimit
//   - Severity: Info (informational, not blocking)
//   - AffectedNamespaces: [object's namespace]
//   - Summary: "Container defaults: CPU 100m-500m, Memory 128Mi-512Mi"
//   - Details: {"type": "Container", "default": {...}, "max": {...}, "min": {...}}
//   - RemediationHint: "Ensure your containers specify resource requests/limits within these bounds"
//
// # Input example
//
//	spec:
//	  limits:
//	  - type: Container
//	    default:
//	      cpu: 500m
//	      memory: 512Mi
//	    defaultRequest:
//	      cpu: 100m
//	      memory: 128Mi
//	    max:
//	      cpu: "2"
//	      memory: 2Gi
//	    min:
//	      cpu: 50m
//	      memory: 64Mi
package limitrange
