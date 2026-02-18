package indexer

import (
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
	"github.com/potooio/potoo/internal/util"
)

// IndexEvent represents a change to the constraint index.
type IndexEvent struct {
	Type       string // "upsert" or "delete"
	Constraint types.Constraint
}

// OnChangeFunc is called when the index changes.
type OnChangeFunc func(event IndexEvent)

// Indexer is a concurrent-safe in-memory store of normalized Constraint objects.
type Indexer struct {
	mu       sync.RWMutex
	byUID    map[k8stypes.UID]types.Constraint
	onChange OnChangeFunc
}

// New creates a new Indexer with an optional change callback.
func New(onChange OnChangeFunc) *Indexer {
	return &Indexer{
		byUID:    make(map[k8stypes.UID]types.Constraint),
		onChange: onChange,
	}
}

// Upsert adds the constraint or replaces an existing one with the same UID.
func (idx *Indexer) Upsert(c types.Constraint) {
	idx.mu.Lock()
	idx.byUID[c.UID] = c
	idx.mu.Unlock()

	if idx.onChange != nil {
		idx.onChange(IndexEvent{Type: "upsert", Constraint: c})
	}
}

// Delete removes the constraint with the given UID. No-op if not found.
func (idx *Indexer) Delete(uid k8stypes.UID) {
	idx.mu.Lock()
	c, exists := idx.byUID[uid]
	if exists {
		delete(idx.byUID, uid)
	}
	idx.mu.Unlock()

	if exists && idx.onChange != nil {
		idx.onChange(IndexEvent{Type: "delete", Constraint: c})
	}
}

// ByNamespace returns all constraints where AffectedNamespaces contains ns,
// OR Namespace == ns, OR the constraint is cluster-scoped (Namespace == "").
func (idx *Indexer) ByNamespace(ns string) []types.Constraint {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var result []types.Constraint
	for _, c := range idx.byUID {
		if idx.matchesNamespace(c, ns) {
			result = append(result, c)
		}
	}
	return result
}

// matchesNamespace checks if a constraint affects the given namespace.
func (idx *Indexer) matchesNamespace(c types.Constraint, ns string) bool {
	// Cluster-scoped constraints (empty namespace) match all namespaces
	if c.Namespace == "" {
		return true
	}
	// Direct namespace match
	if c.Namespace == ns {
		return true
	}
	// Check AffectedNamespaces
	for _, affected := range c.AffectedNamespaces {
		if affected == ns {
			return true
		}
	}
	return false
}

// ByLabels returns constraints from ByNamespace(ns) where WorkloadSelector matches labels.
// A nil WorkloadSelector matches all labels (cluster-wide constraint).
// An empty WorkloadSelector (non-nil, zero matchLabels) also matches all.
func (idx *Indexer) ByLabels(ns string, workloadLabels map[string]string) []types.Constraint {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var result []types.Constraint
	for _, c := range idx.byUID {
		if !idx.matchesNamespace(c, ns) {
			continue
		}
		if idx.matchesLabels(c.WorkloadSelector, workloadLabels) {
			result = append(result, c)
		}
	}
	return result
}

// matchesLabels checks if a workload's labels match the constraint's selector.
func (idx *Indexer) matchesLabels(selector *metav1.LabelSelector, workloadLabels map[string]string) bool {
	return util.MatchesLabelSelector(selector, workloadLabels)
}

// ByType returns all constraints with the given ConstraintType.
func (idx *Indexer) ByType(ct types.ConstraintType) []types.Constraint {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var result []types.Constraint
	for _, c := range idx.byUID {
		if c.ConstraintType == ct {
			result = append(result, c)
		}
	}
	return result
}

// BySourceGVR returns all constraints parsed from the given source GVR.
func (idx *Indexer) BySourceGVR(gvr schema.GroupVersionResource) []types.Constraint {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var result []types.Constraint
	for _, c := range idx.byUID {
		if c.Source == gvr {
			result = append(result, c)
		}
	}
	return result
}

// DeleteBySource removes all constraints originating from the given GVR.
// Used when a ConstraintProfile is deleted to clean up stale constraints.
func (idx *Indexer) DeleteBySource(gvr schema.GroupVersionResource) int {
	idx.mu.Lock()
	var toDelete []k8stypes.UID
	for uid, c := range idx.byUID {
		if c.Source == gvr {
			toDelete = append(toDelete, uid)
		}
	}
	deleted := make([]types.Constraint, 0, len(toDelete))
	for _, uid := range toDelete {
		c := idx.byUID[uid]
		delete(idx.byUID, uid)
		deleted = append(deleted, c)
	}
	idx.mu.Unlock()

	if idx.onChange != nil {
		for _, c := range deleted {
			idx.onChange(IndexEvent{Type: "delete", Constraint: c})
		}
	}
	return len(toDelete)
}

// All returns all stored constraints (copy of the slice).
func (idx *Indexer) All() []types.Constraint {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make([]types.Constraint, 0, len(idx.byUID))
	for _, c := range idx.byUID {
		result = append(result, c)
	}
	return result
}

// Count returns the total number of stored constraints.
func (idx *Indexer) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.byUID)
}
