package adapters

import (
	"fmt"
	"sync"

	"github.com/potooio/potoo/internal/types"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Registry maintains the mapping of GVRs to adapters.
// It is safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]types.Adapter                      // name → adapter
	gvrMap   map[schema.GroupVersionResource]types.Adapter // GVR → adapter
	groupMap map[string]types.Adapter                      // group → first adapter (for dynamic CRDs)
}

// NewRegistry creates an empty adapter registry.
// Call Register() to add adapters, then use in the discovery engine.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]types.Adapter),
		gvrMap:   make(map[schema.GroupVersionResource]types.Adapter),
		groupMap: make(map[string]types.Adapter),
	}
}

// Register adds an adapter to the registry.
// It maps all GVRs returned by adapter.Handles() to this adapter.
// Returns an error if a GVR is already registered to a different adapter.
func (r *Registry) Register(adapter types.Adapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := adapter.Name()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapter %q already registered", name)
	}

	for _, gvr := range adapter.Handles() {
		if existing, exists := r.gvrMap[gvr]; exists {
			return fmt.Errorf("GVR %s already registered to adapter %q, cannot register to %q",
				gvr.String(), existing.Name(), name)
		}
		r.gvrMap[gvr] = adapter

		// Index by group - first adapter for each group wins.
		// This enables O(1) lookup for dynamic CRDs like Gatekeeper constraints.
		if _, exists := r.groupMap[gvr.Group]; !exists {
			r.groupMap[gvr.Group] = adapter
		}
	}

	r.adapters[name] = adapter
	return nil
}

// ForGVR returns the adapter registered for the given GVR, or nil if none.
func (r *Registry) ForGVR(gvr schema.GroupVersionResource) types.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gvrMap[gvr]
}

// ForName returns the adapter with the given name, or nil if none.
func (r *Registry) ForName(name string) types.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adapters[name]
}

// All returns all registered adapters.
func (r *Registry) All() []types.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]types.Adapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		result = append(result, a)
	}
	return result
}

// HandledGVRs returns all GVRs that have a registered adapter.
func (r *Registry) HandledGVRs() []schema.GroupVersionResource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]schema.GroupVersionResource, 0, len(r.gvrMap))
	for gvr := range r.gvrMap {
		result = append(result, gvr)
	}
	return result
}

// Unregister removes an adapter by name, including all its GVR mappings
// (both from Handles() and any added dynamically via RegisterGVR).
// Returns an error if the adapter is not found.
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.adapters[name]; !exists {
		return fmt.Errorf("adapter %q not registered", name)
	}

	// Remove all GVR mappings that point to this adapter,
	// including those added dynamically via RegisterGVR.
	affectedGroups := map[string]bool{}
	for gvr, a := range r.gvrMap {
		if a.Name() == name {
			delete(r.gvrMap, gvr)
			affectedGroups[gvr.Group] = true
		}
	}

	// Clean up groupMap for affected groups, reassigning if another adapter remains.
	for group := range affectedGroups {
		if g, ok := r.groupMap[group]; ok && g.Name() == name {
			reassigned := false
			for gvr, a := range r.gvrMap {
				if gvr.Group == group {
					r.groupMap[group] = a
					reassigned = true
					break
				}
			}
			if !reassigned {
				delete(r.groupMap, group)
			}
		}
	}

	delete(r.adapters, name)
	return nil
}

// RegisterGVR maps a single GVR to an existing adapter.
// If the GVR is already mapped, it is overwritten (update-in-place for ConstraintProfile reconciliation).
func (r *Registry) RegisterGVR(gvr schema.GroupVersionResource, adapter types.Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.gvrMap[gvr] = adapter

	// Index by group — first adapter for each group wins.
	if _, exists := r.groupMap[gvr.Group]; !exists {
		r.groupMap[gvr.Group] = adapter
	}
}

// UnregisterGVR removes the mapping for a single GVR.
func (r *Registry) UnregisterGVR(gvr schema.GroupVersionResource) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if adapter, exists := r.gvrMap[gvr]; exists {
		delete(r.gvrMap, gvr)
		// Clean up groupMap if this was the only GVR for the group
		if g, ok := r.groupMap[gvr.Group]; ok && g.Name() == adapter.Name() {
			// Check if any other GVR in this group still exists
			found := false
			for otherGVR := range r.gvrMap {
				if otherGVR.Group == gvr.Group {
					found = true
					break
				}
			}
			if !found {
				delete(r.groupMap, gvr.Group)
			}
		}
	}
}

// ForGroup returns the adapter that handles resources in the given API group.
// This is useful for policy engines like Gatekeeper that create CRDs dynamically
// (e.g., k8srequiredlabels.constraints.gatekeeper.sh).
// Returns nil if no adapter handles resources in that group.
// Note: If multiple adapters handle the same group, the first registered wins.
func (r *Registry) ForGroup(group string) types.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.groupMap[group]
}
