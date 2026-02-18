// Package indexer provides a concurrent-safe in-memory store of normalized Constraint objects.
//
// # Contract
//
// The Indexer stores Constraint objects keyed by UID. It supports O(1) upsert/delete
// by UID and O(n) queries by namespace, label match, constraint type, and source GVR.
//
// Thread safety: all methods are safe for concurrent use via sync.RWMutex.
//
// # Methods
//
//	Upsert(c types.Constraint)
//	  - Adds the constraint or replaces an existing one with the same UID.
//
//	Delete(uid k8stypes.UID)
//	  - Removes the constraint with the given UID. No-op if not found.
//
//	ByNamespace(ns string) []types.Constraint
//	  - Returns all constraints where AffectedNamespaces contains ns,
//	    OR Namespace == ns, OR the constraint is cluster-scoped (Namespace == "").
//
//	ByLabels(ns string, labels map[string]string) []types.Constraint
//	  - Returns constraints from ByNamespace(ns) where WorkloadSelector matches labels.
//	  - A nil WorkloadSelector matches all labels (cluster-wide constraint).
//	  - An empty WorkloadSelector (non-nil, zero matchLabels) also matches all.
//	  - Use labels.SelectorFromValidatedSet() for matching.
//
//	ByType(ct types.ConstraintType) []types.Constraint
//	  - Returns all constraints with the given ConstraintType.
//
//	BySourceGVR(gvr schema.GroupVersionResource) []types.Constraint
//	  - Returns all constraints parsed from the given source GVR.
//
//	All() []types.Constraint
//	  - Returns all stored constraints (copy of the slice).
//
//	Count() int
//	  - Returns the total number of stored constraints.
//
// # Callback
//
// The Indexer accepts an optional OnChange callback that fires on every Upsert/Delete.
// The notification dispatcher and report reconciler use this to react to index changes.
//
//	type OnChangeFunc func(event IndexEvent)
//	type IndexEvent struct {
//	    Type       string // "upsert" or "delete"
//	    Constraint types.Constraint
//	}
package indexer
