package adapters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/potooio/potoo/internal/types"
)

// fakeAdapter implements types.Adapter for testing.
type fakeAdapter struct {
	name string
	gvrs []schema.GroupVersionResource
}

func (a *fakeAdapter) Name() string                           { return a.name }
func (a *fakeAdapter) Handles() []schema.GroupVersionResource { return a.gvrs }
func (a *fakeAdapter) Parse(_ context.Context, _ *unstructured.Unstructured) ([]types.Constraint, error) {
	return nil, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	assert.Empty(t, r.All())
	assert.Empty(t, r.HandledGVRs())
}

func TestRegister_Success(t *testing.T) {
	r := NewRegistry()
	adapter := &fakeAdapter{
		name: "test-adapter",
		gvrs: []schema.GroupVersionResource{
			{Group: "example.io", Version: "v1", Resource: "widgets"},
		},
	}

	err := r.Register(adapter)
	require.NoError(t, err)

	assert.Len(t, r.All(), 1)
	assert.Len(t, r.HandledGVRs(), 1)
}

func TestRegister_DuplicateName(t *testing.T) {
	r := NewRegistry()
	adapter1 := &fakeAdapter{
		name: "same-name",
		gvrs: []schema.GroupVersionResource{
			{Group: "a.io", Version: "v1", Resource: "foos"},
		},
	}
	adapter2 := &fakeAdapter{
		name: "same-name",
		gvrs: []schema.GroupVersionResource{
			{Group: "b.io", Version: "v1", Resource: "bars"},
		},
	}

	err := r.Register(adapter1)
	require.NoError(t, err)

	err = r.Register(adapter2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegister_DuplicateGVR(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "shared.io", Version: "v1", Resource: "things"}

	adapter1 := &fakeAdapter{name: "adapter-a", gvrs: []schema.GroupVersionResource{gvr}}
	adapter2 := &fakeAdapter{name: "adapter-b", gvrs: []schema.GroupVersionResource{gvr}}

	err := r.Register(adapter1)
	require.NoError(t, err)

	err = r.Register(adapter2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered to adapter")
}

func TestRegister_MultipleGVRs(t *testing.T) {
	r := NewRegistry()
	adapter := &fakeAdapter{
		name: "multi-gvr",
		gvrs: []schema.GroupVersionResource{
			{Group: "example.io", Version: "v1", Resource: "foos"},
			{Group: "example.io", Version: "v1", Resource: "bars"},
			{Group: "other.io", Version: "v2", Resource: "bazzes"},
		},
	}

	err := r.Register(adapter)
	require.NoError(t, err)

	assert.Len(t, r.HandledGVRs(), 3)
	assert.Len(t, r.All(), 1)
}

func TestForGVR(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "widgets"}
	adapter := &fakeAdapter{name: "widget-adapter", gvrs: []schema.GroupVersionResource{gvr}}

	err := r.Register(adapter)
	require.NoError(t, err)

	// Found
	result := r.ForGVR(gvr)
	require.NotNil(t, result)
	assert.Equal(t, "widget-adapter", result.Name())

	// Not found
	result = r.ForGVR(schema.GroupVersionResource{Group: "other.io", Version: "v1", Resource: "missing"})
	assert.Nil(t, result)
}

func TestForName(t *testing.T) {
	r := NewRegistry()
	adapter := &fakeAdapter{
		name: "my-adapter",
		gvrs: []schema.GroupVersionResource{
			{Group: "test.io", Version: "v1", Resource: "foos"},
		},
	}

	err := r.Register(adapter)
	require.NoError(t, err)

	// Found
	result := r.ForName("my-adapter")
	require.NotNil(t, result)
	assert.Equal(t, "my-adapter", result.Name())

	// Not found
	result = r.ForName("nonexistent")
	assert.Nil(t, result)
}

func TestAll(t *testing.T) {
	r := NewRegistry()

	// Empty registry
	assert.Empty(t, r.All())

	// Register multiple adapters
	for _, name := range []string{"adapter-a", "adapter-b", "adapter-c"} {
		err := r.Register(&fakeAdapter{
			name: name,
			gvrs: []schema.GroupVersionResource{
				{Group: name + ".io", Version: "v1", Resource: "things"},
			},
		})
		require.NoError(t, err)
	}

	all := r.All()
	assert.Len(t, all, 3)

	names := make(map[string]bool)
	for _, a := range all {
		names[a.Name()] = true
	}
	assert.True(t, names["adapter-a"])
	assert.True(t, names["adapter-b"])
	assert.True(t, names["adapter-c"])
}

func TestHandledGVRs(t *testing.T) {
	r := NewRegistry()
	gvr1 := schema.GroupVersionResource{Group: "a.io", Version: "v1", Resource: "foos"}
	gvr2 := schema.GroupVersionResource{Group: "b.io", Version: "v1", Resource: "bars"}

	err := r.Register(&fakeAdapter{name: "a", gvrs: []schema.GroupVersionResource{gvr1}})
	require.NoError(t, err)
	err = r.Register(&fakeAdapter{name: "b", gvrs: []schema.GroupVersionResource{gvr2}})
	require.NoError(t, err)

	gvrs := r.HandledGVRs()
	assert.Len(t, gvrs, 2)

	gvrSet := make(map[string]bool)
	for _, g := range gvrs {
		gvrSet[g.String()] = true
	}
	assert.True(t, gvrSet[gvr1.String()])
	assert.True(t, gvrSet[gvr2.String()])
}

func TestForGroup(t *testing.T) {
	r := NewRegistry()

	adapter := &fakeAdapter{
		name: "gatekeeper",
		gvrs: []schema.GroupVersionResource{
			{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Resource: "k8srequiredlabels"},
		},
	}

	err := r.Register(adapter)
	require.NoError(t, err)

	// Should find by group
	result := r.ForGroup("constraints.gatekeeper.sh")
	require.NotNil(t, result)
	assert.Equal(t, "gatekeeper", result.Name())

	// Not found
	result = r.ForGroup("unknown.io")
	assert.Nil(t, result)
}

func TestForGroup_FirstAdapterWins(t *testing.T) {
	r := NewRegistry()

	// First adapter registers a GVR with group "example.io"
	adapter1 := &fakeAdapter{
		name: "first",
		gvrs: []schema.GroupVersionResource{
			{Group: "example.io", Version: "v1", Resource: "foos"},
		},
	}
	// Second adapter registers a different GVR but same group
	adapter2 := &fakeAdapter{
		name: "second",
		gvrs: []schema.GroupVersionResource{
			{Group: "example.io", Version: "v1", Resource: "bars"},
		},
	}

	err := r.Register(adapter1)
	require.NoError(t, err)
	err = r.Register(adapter2)
	require.NoError(t, err)

	// First registered adapter should win for group lookup
	result := r.ForGroup("example.io")
	require.NotNil(t, result)
	assert.Equal(t, "first", result.Name())
}

func TestUnregister_Success(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "things"}
	adapter := &fakeAdapter{name: "removable", gvrs: []schema.GroupVersionResource{gvr}}

	require.NoError(t, r.Register(adapter))
	assert.Len(t, r.All(), 1)
	assert.NotNil(t, r.ForGVR(gvr))

	err := r.Unregister("removable")
	require.NoError(t, err)
	assert.Empty(t, r.All())
	assert.Nil(t, r.ForGVR(gvr))
	assert.Nil(t, r.ForName("removable"))
	assert.Nil(t, r.ForGroup("test.io"))
}

func TestUnregister_NotFound(t *testing.T) {
	r := NewRegistry()
	err := r.Unregister("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestRegisterGVR(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "dynamic.io", Version: "v1", Resource: "customs"}
	adapter := &fakeAdapter{name: "generic", gvrs: nil}

	require.NoError(t, r.Register(adapter))

	r.RegisterGVR(gvr, adapter)
	assert.Equal(t, "generic", r.ForGVR(gvr).Name())
}

func TestRegisterGVR_Overwrite(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "shared.io", Version: "v1", Resource: "things"}
	adapter1 := &fakeAdapter{name: "first", gvrs: []schema.GroupVersionResource{gvr}}
	adapter2 := &fakeAdapter{name: "second", gvrs: nil}

	require.NoError(t, r.Register(adapter1))
	require.NoError(t, r.Register(adapter2))

	// Overwrite gvr to point to adapter2
	r.RegisterGVR(gvr, adapter2)
	assert.Equal(t, "second", r.ForGVR(gvr).Name())
}

func TestUnregisterGVR(t *testing.T) {
	r := NewRegistry()
	gvr := schema.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "things"}
	adapter := &fakeAdapter{name: "owner", gvrs: nil}

	require.NoError(t, r.Register(adapter))
	r.RegisterGVR(gvr, adapter)
	assert.NotNil(t, r.ForGVR(gvr))

	r.UnregisterGVR(gvr)
	assert.Nil(t, r.ForGVR(gvr))
	assert.Nil(t, r.ForGroup("test.io"), "group map should be cleaned up")
}

func TestUnregisterGVR_PreservesOtherGVRsInGroup(t *testing.T) {
	r := NewRegistry()
	gvr1 := schema.GroupVersionResource{Group: "shared.io", Version: "v1", Resource: "foos"}
	gvr2 := schema.GroupVersionResource{Group: "shared.io", Version: "v1", Resource: "bars"}
	adapter := &fakeAdapter{name: "multi", gvrs: nil}

	require.NoError(t, r.Register(adapter))
	r.RegisterGVR(gvr1, adapter)
	r.RegisterGVR(gvr2, adapter)

	r.UnregisterGVR(gvr1)
	assert.Nil(t, r.ForGVR(gvr1))
	assert.NotNil(t, r.ForGVR(gvr2), "other GVR in same group should remain")
	assert.NotNil(t, r.ForGroup("shared.io"), "group map should survive if other GVRs remain")
}

func TestUnregister_CleansUpDynamicGVRs(t *testing.T) {
	r := NewRegistry()
	adapter := &fakeAdapter{name: "dynamic", gvrs: nil} // no static Handles
	require.NoError(t, r.Register(adapter))

	// Dynamically register GVRs
	gvr1 := schema.GroupVersionResource{Group: "dyn.io", Version: "v1", Resource: "foos"}
	gvr2 := schema.GroupVersionResource{Group: "dyn.io", Version: "v1", Resource: "bars"}
	r.RegisterGVR(gvr1, adapter)
	r.RegisterGVR(gvr2, adapter)
	assert.NotNil(t, r.ForGVR(gvr1))
	assert.NotNil(t, r.ForGVR(gvr2))

	// Unregister should clean up dynamically added GVRs too
	err := r.Unregister("dynamic")
	require.NoError(t, err)
	assert.Nil(t, r.ForGVR(gvr1), "dynamically registered GVR should be cleaned up")
	assert.Nil(t, r.ForGVR(gvr2), "dynamically registered GVR should be cleaned up")
	assert.Nil(t, r.ForGroup("dyn.io"), "group should be cleaned up")
}

func TestRegister_NoGVRs(t *testing.T) {
	r := NewRegistry()
	adapter := &fakeAdapter{
		name: "no-gvrs",
		gvrs: nil, // Like the generic adapter
	}

	err := r.Register(adapter)
	require.NoError(t, err)

	assert.Len(t, r.All(), 1)
	assert.Empty(t, r.HandledGVRs())

	// Should be findable by name
	result := r.ForName("no-gvrs")
	require.NotNil(t, result)
}
