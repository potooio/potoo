// Package resourcequota provides a constraint adapter for core/v1 ResourceQuota
// and core/v1 LimitRange objects.
//
// # ResourceQuota Parsing
//
// Handles GVR: {"", "v1", "resourcequotas"}
//
// Reads `spec.hard` (limits) and `status.used` (current usage).
// Computes usage percentage for each resource type (cpu, memory, pods, etc.).
//
// Produces ONE Constraint per ResourceQuota with:
//   - ConstraintType: ResourceLimit
//   - Severity: Info (<75%), Warning (75-90%), Critical (>90%) — based on highest usage
//   - AffectedNamespaces: [quota's namespace]
//   - Summary: "CPU: 3.2/4 cores (80%); Memory: 6.1/8Gi (76%)"
//   - Details: {"resources": {"cpu": {"hard": "4", "used": "3.2", "percent": 80}, ...}}
//   - RemediationHint: "Request quota increase or reduce resource usage"
//
// If `status.used` is not yet populated (newly created quota), Severity is Info.
//
// # Input examples
//
//	spec:
//	  hard:
//	    cpu: "4"
//	    memory: 8Gi
//	    pods: "20"
//	status:
//	  hard:
//	    cpu: "4"
//	    memory: 8Gi
//	    pods: "20"
//	  used:
//	    cpu: "3200m"
//	    memory: 6Gi
//	    pods: "15"
package resourcequota
