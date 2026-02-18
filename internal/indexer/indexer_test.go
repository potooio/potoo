package indexer

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/types"
)

func makeConstraint(uid string, ns string, ct types.ConstraintType, labels map[string]string) types.Constraint {
	var selector *metav1.LabelSelector
	if labels != nil {
		selector = &metav1.LabelSelector{MatchLabels: labels}
	}
	return types.Constraint{
		UID:                k8stypes.UID(uid),
		Name:               "test-" + uid,
		Namespace:          ns,
		AffectedNamespaces: []string{ns},
		WorkloadSelector:   selector,
		ConstraintType:     ct,
		Source:             schema.GroupVersionResource{Group: "test", Version: "v1", Resource: "tests"},
	}
}

func TestUpsertAndCount(t *testing.T) {
	idx := New(nil)
	assert.Equal(t, 0, idx.Count())

	c1 := makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil)
	idx.Upsert(c1)
	assert.Equal(t, 1, idx.Count())

	// Upsert same UID replaces, count stays 1
	c1.Summary = "updated"
	idx.Upsert(c1)
	assert.Equal(t, 1, idx.Count())

	c2 := makeConstraint("uid-2", "ns-a", types.ConstraintTypeAdmission, nil)
	idx.Upsert(c2)
	assert.Equal(t, 2, idx.Count())
}

func TestDelete(t *testing.T) {
	idx := New(nil)
	c := makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil)
	idx.Upsert(c)
	assert.Equal(t, 1, idx.Count())

	idx.Delete(k8stypes.UID("uid-1"))
	assert.Equal(t, 0, idx.Count())

	// Deleting nonexistent UID is a no-op
	idx.Delete(k8stypes.UID("nonexistent"))
	assert.Equal(t, 0, idx.Count())
}

func TestByNamespace(t *testing.T) {
	idx := New(nil)
	idx.Upsert(makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil))
	idx.Upsert(makeConstraint("uid-2", "ns-b", types.ConstraintTypeNetworkEgress, nil))
	idx.Upsert(makeConstraint("uid-3", "ns-a", types.ConstraintTypeAdmission, nil))

	nsA := idx.ByNamespace("ns-a")
	assert.Len(t, nsA, 2)

	nsB := idx.ByNamespace("ns-b")
	assert.Len(t, nsB, 1)

	nsC := idx.ByNamespace("ns-c")
	assert.Len(t, nsC, 0)
}

func TestByNamespace_ClusterScoped(t *testing.T) {
	idx := New(nil)

	// Cluster-scoped constraint (empty namespace) should appear in ALL namespace queries
	clusterWide := types.Constraint{
		UID:                k8stypes.UID("uid-cluster"),
		Name:               "cluster-policy",
		Namespace:          "", // cluster-scoped
		AffectedNamespaces: nil,
		ConstraintType:     types.ConstraintTypeAdmission,
	}
	idx.Upsert(clusterWide)

	idx.Upsert(makeConstraint("uid-ns", "ns-a", types.ConstraintTypeNetworkEgress, nil))

	// ns-a should see both its own constraint AND the cluster-scoped one
	nsA := idx.ByNamespace("ns-a")
	assert.Len(t, nsA, 2)

	// Any namespace should see the cluster-scoped constraint
	nsX := idx.ByNamespace("ns-x")
	assert.Len(t, nsX, 1)
	assert.Equal(t, "cluster-policy", nsX[0].Name)
}

func TestByType(t *testing.T) {
	idx := New(nil)
	idx.Upsert(makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil))
	idx.Upsert(makeConstraint("uid-2", "ns-a", types.ConstraintTypeNetworkEgress, nil))
	idx.Upsert(makeConstraint("uid-3", "ns-a", types.ConstraintTypeAdmission, nil))

	egress := idx.ByType(types.ConstraintTypeNetworkEgress)
	assert.Len(t, egress, 2)

	admission := idx.ByType(types.ConstraintTypeAdmission)
	assert.Len(t, admission, 1)

	mesh := idx.ByType(types.ConstraintTypeMeshPolicy)
	assert.Len(t, mesh, 0)
}

func TestByLabels(t *testing.T) {
	idx := New(nil)

	// Constraint that targets app=web
	idx.Upsert(makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress,
		map[string]string{"app": "web"}))

	// Constraint that targets app=api
	idx.Upsert(makeConstraint("uid-2", "ns-a", types.ConstraintTypeNetworkEgress,
		map[string]string{"app": "api"}))

	// Constraint with nil selector (matches everything in namespace)
	idx.Upsert(makeConstraint("uid-3", "ns-a", types.ConstraintTypeAdmission, nil))

	// Workload with app=web should match uid-1 and uid-3 (nil selector = match all)
	webMatches := idx.ByLabels("ns-a", map[string]string{"app": "web"})
	assert.Len(t, webMatches, 2)

	// Workload with app=api should match uid-2 and uid-3
	apiMatches := idx.ByLabels("ns-a", map[string]string{"app": "api"})
	assert.Len(t, apiMatches, 2)

	// Workload with app=db should match only uid-3 (nil selector)
	dbMatches := idx.ByLabels("ns-a", map[string]string{"app": "db"})
	assert.Len(t, dbMatches, 1)

	// Wrong namespace should match nothing
	wrongNS := idx.ByLabels("ns-b", map[string]string{"app": "web"})
	assert.Len(t, wrongNS, 0)
}

func TestBySourceGVR(t *testing.T) {
	idx := New(nil)

	c1 := makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil)
	c1.Source = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	idx.Upsert(c1)

	c2 := makeConstraint("uid-2", "ns-a", types.ConstraintTypeResourceLimit, nil)
	c2.Source = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"}
	idx.Upsert(c2)

	np := idx.BySourceGVR(schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"})
	assert.Len(t, np, 1)

	rq := idx.BySourceGVR(schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"})
	assert.Len(t, rq, 1)
}

func TestAll(t *testing.T) {
	idx := New(nil)
	idx.Upsert(makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil))
	idx.Upsert(makeConstraint("uid-2", "ns-b", types.ConstraintTypeAdmission, nil))

	all := idx.All()
	assert.Len(t, all, 2)
}

func TestOnChangeCallback(t *testing.T) {
	var events []IndexEvent
	var mu sync.Mutex

	callback := func(e IndexEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	idx := New(callback)

	c := makeConstraint("uid-1", "ns-a", types.ConstraintTypeNetworkEgress, nil)
	idx.Upsert(c)
	idx.Delete(k8stypes.UID("uid-1"))

	mu.Lock()
	require.Len(t, events, 2)
	assert.Equal(t, "upsert", events[0].Type)
	assert.Equal(t, "delete", events[1].Type)
	mu.Unlock()
}

func TestConcurrency(t *testing.T) {
	idx := New(nil)
	var wg sync.WaitGroup

	// Concurrent upserts
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := makeConstraint(
				fmt.Sprintf("%c-%d", 'a'+i%26, i%10),
				"ns-a",
				types.ConstraintTypeNetworkEgress,
				nil,
			)
			idx.Upsert(c)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = idx.ByNamespace("ns-a")
			_ = idx.All()
			_ = idx.Count()
		}()
	}

	wg.Wait()
	// No panic = success
	assert.True(t, idx.Count() > 0)
}
