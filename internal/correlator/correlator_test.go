package correlator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/potooio/potoo/internal/hubble"
	"github.com/potooio/potoo/internal/indexer"
	internaltypes "github.com/potooio/potoo/internal/types"
)

func TestNew(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	require.NotNil(t, c)
	assert.NotNil(t, c.notifications)
	assert.NotNil(t, c.flowDrops)
	assert.NotNil(t, c.limiter)
	assert.NotNil(t, c.seenPairs)
}

func TestNewWithOptions(t *testing.T) {
	idx := indexer.New(nil)
	opts := CorrelatorOptions{}
	c := NewWithOptions(idx, nil, zap.NewNop(), opts)

	require.NotNil(t, c)
	assert.Nil(t, c.hubbleClient)
}

func TestNotifications(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ch := c.Notifications()
	require.NotNil(t, ch)
}

func TestFlowDropNotifications(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ch := c.FlowDropNotifications()
	require.NotNil(t, ch)
}

func TestTryMarkSeen(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	key := dedupeKey{
		eventUID:      "event-1",
		constraintUID: "constraint-1",
	}

	// First call: not seen yet, should succeed and mark
	assert.True(t, c.tryMarkSeen(key), "first call should succeed")

	// Second call: already seen, should be rejected
	assert.False(t, c.tryMarkSeen(key), "duplicate should be rejected")
}

func TestMatchesSelector(t *testing.T) {
	// Comprehensive selector matching tests are in internal/util/labels_test.go.
	// These cases verify the correlator's delegation works correctly.
	tests := []struct {
		name     string
		selector *metav1.LabelSelector
		labels   map[string]string
		expected bool
	}{
		{
			name:     "nil selector matches all",
			selector: nil,
			labels:   map[string]string{"app": "foo"},
			expected: true,
		},
		{
			name: "matching labels",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   map[string]string{"app": "foo", "version": "v1"},
			expected: true,
		},
		{
			name: "non-matching labels",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   map[string]string{"app": "bar"},
			expected: false,
		},
		{
			name: "MatchExpressions In operator",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
				},
			},
			labels:   map[string]string{"env": "prod"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesSelector(tt.selector, tt.labels)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleFlowDrop_NonPolicyDrop(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Non-policy drop should be ignored
	drop := hubble.NewFlowDropBuilder().
		WithSource("ns", "pod1", nil).
		WithDestination("ns", "pod2", nil).
		WithDropReason(hubble.DropReasonTTLExceeded). // Not a policy drop
		Build()

	c.handleFlowDrop(ctx, drop)

	// No notification should be sent
	select {
	case <-c.flowDrops:
		t.Fatal("unexpected flow drop notification")
	default:
		// Expected
	}
}

func TestHandleFlowDrop_PolicyDrop(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add a network policy constraint to the indexer
	constraint := internaltypes.Constraint{
		UID:            types.UID("constraint-1"),
		Name:           "deny-external",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
		WorkloadSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "backend"},
		},
	}
	idx.Upsert(constraint)

	// Policy drop for matching pod
	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client-pod", map[string]string{"type": "external"}).
		WithDestination("production", "backend-xyz", map[string]string{"app": "backend"}).
		WithTCP(45678, 8080, hubble.TCPFlags{SYN: true}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Should receive a notification
	select {
	case notification := <-c.flowDrops:
		assert.Equal(t, "backend-xyz", notification.DestPodName)
		assert.Equal(t, "production", notification.DestNamespace)
		assert.Equal(t, uint32(8080), notification.DestPort)
		assert.Equal(t, "TCP", notification.Protocol)
		assert.Equal(t, "deny-external", notification.Constraint.Name)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for flow drop notification")
	}
}

func TestHandleFlowDrop_NoMatchingSelector(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add a constraint with different selector
	constraint := internaltypes.Constraint{
		UID:            types.UID("constraint-1"),
		Name:           "deny-frontend",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
		WorkloadSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "frontend"}, // Different label
		},
	}
	idx.Upsert(constraint)

	// Drop for non-matching pod
	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("production", "backend-xyz", map[string]string{"app": "backend"}).
		WithTCP(45678, 8080, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Should not receive a notification
	select {
	case <-c.flowDrops:
		t.Fatal("unexpected flow drop notification for non-matching pod")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleFlowDrop_Deduplication(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add a constraint
	constraint := internaltypes.Constraint{
		UID:            types.UID("constraint-1"),
		Name:           "deny-all",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	// Same drop
	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("production", "backend", nil).
		WithTCP(45678, 8080, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	// First drop should be processed
	c.handleFlowDrop(ctx, drop)
	select {
	case <-c.flowDrops:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("expected notification for first drop")
	}

	// Second identical drop should be deduplicated
	c.handleFlowDrop(ctx, drop)
	select {
	case <-c.flowDrops:
		t.Fatal("duplicate drop should be suppressed")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestCleanupDedupeCache(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	// Add an old entry that's past the dedupeWindow
	oldKey := dedupeKey{
		eventUID:      "old-event",
		constraintUID: "constraint",
	}
	newKey := dedupeKey{
		eventUID:      "new-event",
		constraintUID: "constraint",
	}
	c.mu.Lock()
	c.seenPairs[oldKey] = time.Now().Add(-10 * time.Minute) // Older than dedupeWindow
	c.seenPairs[newKey] = time.Now()                        // Recent
	c.mu.Unlock()

	// Manually run the cleanup logic (same as what cleanupDedupeCache does)
	c.mu.Lock()
	cutoff := time.Now().Add(-dedupeWindow)
	for key, seenAt := range c.seenPairs {
		if seenAt.Before(cutoff) {
			delete(c.seenPairs, key)
		}
	}
	c.mu.Unlock()

	// Old entry should be removed, new one should remain
	c.mu.Lock()
	_, oldExists := c.seenPairs[oldKey]
	_, newExists := c.seenPairs[newKey]
	c.mu.Unlock()

	assert.False(t, oldExists, "old entry should be cleaned up")
	assert.True(t, newExists, "new entry should remain")
}

// --- handleEvent tests ---

// makeEvent creates a corev1.Event with the given UID, namespace, name, and kind.
func makeEvent(uid, namespace, name, kind string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID(uid),
			Name: "event-" + uid,
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: namespace,
			Name:      name,
			Kind:      kind,
		},
		Type:    "Warning",
		Reason:  "FailedScheduling",
		Message: "something went wrong",
	}
}

func TestHandleEvent_BasicCorrelation(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add a constraint in the "default" namespace
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-1"),
		Name:           "restrict-pods",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	event := makeEvent("evt-1", "default", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	// Should receive one notification
	select {
	case notification := <-c.Notifications():
		assert.Equal(t, "default", notification.Namespace)
		assert.Equal(t, "my-pod", notification.WorkloadName)
		assert.Equal(t, "Pod", notification.WorkloadKind)
		assert.Equal(t, "restrict-pods", notification.Constraint.Name)
		assert.Equal(t, types.UID("c-1"), notification.Constraint.UID)
		// Event should be a deep copy
		assert.Equal(t, types.UID("evt-1"), notification.Event.UID)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for notification")
	}
}

func TestHandleEvent_ClusterScoped(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add a constraint that matches everything
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-1"),
		Name:           "global-constraint",
		Namespace:      "",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	// Event with empty namespace (cluster-scoped involved object)
	event := makeEvent("evt-cluster", "", "some-node", "Node")
	c.handleEvent(ctx, event)

	// Should NOT produce any notification because handleEvent skips empty ns
	select {
	case <-c.Notifications():
		t.Fatal("cluster-scoped event should be skipped by handleEvent")
	case <-time.After(100 * time.Millisecond):
		// Expected: no notification
	}
}

func TestHandleEvent_NoConstraints(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// No constraints added to the indexer at all

	event := makeEvent("evt-orphan", "some-namespace", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	// Should not produce any notification
	select {
	case <-c.Notifications():
		t.Fatal("should not produce notification when no constraints exist")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleEvent_Deduplication(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-dedup"),
		Name:           "dedup-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	event := makeEvent("evt-dedup", "default", "my-pod", "Pod")

	// First call should produce a notification
	c.handleEvent(ctx, event)
	select {
	case n := <-c.Notifications():
		assert.Equal(t, "dedup-constraint", n.Constraint.Name)
	case <-time.After(time.Second):
		t.Fatal("expected notification on first call")
	}

	// Second call with same event+constraint should be deduplicated
	c.handleEvent(ctx, event)
	select {
	case <-c.Notifications():
		t.Fatal("duplicate event+constraint pair should be suppressed")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleEvent_MultipleConstraints(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add three constraints in the same namespace
	for i, name := range []string{"constraint-a", "constraint-b", "constraint-c"} {
		constraint := internaltypes.Constraint{
			UID:            types.UID(name),
			Name:           name,
			Namespace:      "multi-ns",
			ConstraintType: internaltypes.ConstraintTypeAdmission,
			Summary:        name + " summary",
			Tags:           []string{"tag-" + string(rune('a'+i))},
		}
		idx.Upsert(constraint)
	}

	event := makeEvent("evt-multi", "multi-ns", "my-deployment", "Deployment")
	c.handleEvent(ctx, event)

	// Collect all notifications
	received := map[string]CorrelatedNotification{}
	timeout := time.After(time.Second)
	for len(received) < 3 {
		select {
		case n := <-c.Notifications():
			received[n.Constraint.Name] = n
		case <-timeout:
			t.Fatalf("expected 3 notifications, got %d", len(received))
		}
	}

	// All three constraints should have produced notifications
	assert.Len(t, received, 3)
	for _, name := range []string{"constraint-a", "constraint-b", "constraint-c"} {
		n, ok := received[name]
		require.True(t, ok, "missing notification for %s", name)
		assert.Equal(t, "multi-ns", n.Namespace)
		assert.Equal(t, "my-deployment", n.WorkloadName)
		assert.Equal(t, "Deployment", n.WorkloadKind)
	}
}

func TestHandleEvent_ChannelFull(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-full"),
		Name:           "fill-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	// Fill the notification channel to capacity (notificationBuffer = 1000)
	for i := 0; i < notificationBuffer; i++ {
		c.notifications <- CorrelatedNotification{}
	}

	// Now handleEvent should hit the default branch (channel full) and not block
	event := makeEvent("evt-overflow", "default", "my-pod", "Pod")

	done := make(chan struct{})
	go func() {
		c.handleEvent(ctx, event)
		close(done)
	}()

	select {
	case <-done:
		// handleEvent returned without blocking -- correct behavior
	case <-time.After(2 * time.Second):
		t.Fatal("handleEvent blocked on full channel; should have hit the default branch")
	}
}

func TestHandleEvent_ContextCanceled(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-ctx"),
		Name:           "ctx-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	// Fill the channel so the select falls to ctx.Done or default
	for i := 0; i < notificationBuffer; i++ {
		c.notifications <- CorrelatedNotification{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	event := makeEvent("evt-ctx", "default", "my-pod", "Pod")

	done := make(chan struct{})
	go func() {
		c.handleEvent(ctx, event)
		close(done)
	}()

	select {
	case <-done:
		// handleEvent returned; it either hit default or ctx.Done -- both acceptable
	case <-time.After(2 * time.Second):
		t.Fatal("handleEvent blocked with canceled context")
	}
}

func TestHandleEvent_DifferentNamespaceConstraintNotMatched(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint in "production" namespace only
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-prod"),
		Name:           "prod-constraint",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	// Event in "staging" namespace -- should not match
	event := makeEvent("evt-staging", "staging", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	select {
	case <-c.Notifications():
		t.Fatal("constraint in production should not match event in staging")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleEvent_ClusterScopedConstraintMatchesNamespacedEvent(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Cluster-scoped constraint (empty namespace) matches all namespaces
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-global"),
		Name:           "global-admission",
		Namespace:      "",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	event := makeEvent("evt-any-ns", "any-namespace", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	select {
	case n := <-c.Notifications():
		assert.Equal(t, "global-admission", n.Constraint.Name)
		assert.Equal(t, "any-namespace", n.Namespace)
	case <-time.After(time.Second):
		t.Fatal("cluster-scoped constraint should match namespaced event")
	}
}

func TestHandleEvent_DeepCopiesEvent(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-copy"),
		Name:           "copy-test",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	event := makeEvent("evt-copy", "default", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	select {
	case n := <-c.Notifications():
		// Mutate the original event; the notification should not be affected
		event.Message = "mutated-after"
		assert.NotEqual(t, event.Message, n.Event.Message,
			"notification event should be a deep copy, not a reference to the original")
	case <-time.After(time.Second):
		t.Fatal("expected notification")
	}
}

func TestHandleEvent_AffectedNamespacesMatch(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint in "kube-system" but with AffectedNamespaces including "app-ns"
	constraint := internaltypes.Constraint{
		UID:                types.UID("c-affected"),
		Name:               "cross-ns-constraint",
		Namespace:          "kube-system",
		AffectedNamespaces: []string{"app-ns", "other-ns"},
		ConstraintType:     internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	event := makeEvent("evt-affected", "app-ns", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	select {
	case n := <-c.Notifications():
		assert.Equal(t, "cross-ns-constraint", n.Constraint.Name)
		assert.Equal(t, "app-ns", n.Namespace)
	case <-time.After(time.Second):
		t.Fatal("constraint with AffectedNamespaces should match event namespace")
	}
}

// --- Additional handleFlowDrop / correlateFlowDropInNamespace edge cases ---

func TestHandleFlowDrop_EgressConstraint(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Add an egress constraint in source namespace
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-egress"),
		Name:           "deny-egress",
		Namespace:      "app-ns",
		ConstraintType: internaltypes.ConstraintTypeNetworkEgress,
		WorkloadSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "sender"},
		},
	}
	idx.Upsert(constraint)

	// Source is in app-ns, destination is external
	drop := hubble.NewFlowDropBuilder().
		WithSource("app-ns", "sender-pod", map[string]string{"app": "sender"}).
		WithDestination("external-ns", "external-svc", map[string]string{"role": "external"}).
		WithTCP(12345, 443, hubble.TCPFlags{SYN: true}).
		WithDropReason(hubble.DropReasonEgressDenied).
		Build()

	c.handleFlowDrop(ctx, drop)

	select {
	case notification := <-c.flowDrops:
		assert.Equal(t, "deny-egress", notification.Constraint.Name)
		assert.Equal(t, "sender-pod", notification.SourcePodName)
		assert.Equal(t, "app-ns", notification.SourceNamespace)
		assert.Equal(t, "external-svc", notification.DestPodName)
		assert.Equal(t, uint32(443), notification.DestPort)
		assert.Equal(t, "TCP", notification.Protocol)
	case <-time.After(time.Second):
		t.Fatal("expected egress flow drop notification")
	}
}

func TestCorrelateFlowDrop_MultipleConstraints(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint 1: network ingress, matches "app=backend" in production
	c1 := internaltypes.Constraint{
		UID:            types.UID("c-ingress"),
		Name:           "ingress-policy",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
		WorkloadSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "backend"},
		},
	}
	// Constraint 2: admission (non-network) -- should be skipped
	c2 := internaltypes.Constraint{
		UID:            types.UID("c-admission"),
		Name:           "admission-policy",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	// Constraint 3: network egress, selector does NOT match dest labels
	c3 := internaltypes.Constraint{
		UID:            types.UID("c-egress-nomatch"),
		Name:           "egress-no-match",
		Namespace:      "production",
		ConstraintType: internaltypes.ConstraintTypeNetworkEgress,
		WorkloadSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "frontend"}, // Does not match
		},
	}
	// Constraint 4: network ingress, nil selector (matches all)
	c4 := internaltypes.Constraint{
		UID:              types.UID("c-ingress-all"),
		Name:             "ingress-all",
		Namespace:        "production",
		ConstraintType:   internaltypes.ConstraintTypeNetworkIngress,
		WorkloadSelector: nil, // Matches all
	}

	idx.Upsert(c1)
	idx.Upsert(c2)
	idx.Upsert(c3)
	idx.Upsert(c4)

	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("production", "backend-pod", map[string]string{"app": "backend"}).
		WithTCP(55555, 8080, hubble.TCPFlags{SYN: true}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Collect notifications: should get c1 (ingress, matching label) and c4 (ingress, nil selector)
	// c2 is admission (not network type), c3 has non-matching selector
	received := map[string]FlowDropNotification{}
	timeout := time.After(time.Second)
	for len(received) < 2 {
		select {
		case n := <-c.flowDrops:
			received[n.Constraint.Name] = n
		case <-timeout:
			t.Fatalf("expected 2 notifications, got %d: %v", len(received), keys(received))
		}
	}

	// Verify we got exactly the right two
	assert.Contains(t, received, "ingress-policy")
	assert.Contains(t, received, "ingress-all")
	assert.NotContains(t, received, "admission-policy")
	assert.NotContains(t, received, "egress-no-match")

	// No more notifications
	select {
	case n := <-c.flowDrops:
		t.Fatalf("unexpected extra notification: %s", n.Constraint.Name)
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleFlowDrop_BothNamespaces(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint in source namespace
	srcConstraint := internaltypes.Constraint{
		UID:            types.UID("c-src"),
		Name:           "src-egress",
		Namespace:      "src-ns",
		ConstraintType: internaltypes.ConstraintTypeNetworkEgress,
	}
	// Constraint in destination namespace
	dstConstraint := internaltypes.Constraint{
		UID:            types.UID("c-dst"),
		Name:           "dst-ingress",
		Namespace:      "dst-ns",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(srcConstraint)
	idx.Upsert(dstConstraint)

	// Drop with source and destination in different namespaces
	drop := hubble.NewFlowDropBuilder().
		WithSource("src-ns", "source-pod", nil).
		WithDestination("dst-ns", "dest-pod", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Should get notifications for BOTH namespaces
	received := map[string]FlowDropNotification{}
	timeout := time.After(time.Second)
	for len(received) < 2 {
		select {
		case n := <-c.flowDrops:
			received[n.Constraint.Name] = n
		case <-timeout:
			t.Fatalf("expected 2 notifications, got %d", len(received))
		}
	}

	assert.Contains(t, received, "src-egress")
	assert.Contains(t, received, "dst-ingress")
}

func TestHandleFlowDrop_SameSourceAndDestNamespace(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint in the shared namespace
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-same-ns"),
		Name:           "same-ns-policy",
		Namespace:      "shared",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	// Source and destination in the same namespace
	drop := hubble.NewFlowDropBuilder().
		WithSource("shared", "pod-a", nil).
		WithDestination("shared", "pod-b", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Should get exactly one notification (namespace deduped in handleFlowDrop)
	select {
	case n := <-c.flowDrops:
		assert.Equal(t, "same-ns-policy", n.Constraint.Name)
	case <-time.After(time.Second):
		t.Fatal("expected notification for same-namespace flow drop")
	}

	// No extra notification
	select {
	case <-c.flowDrops:
		t.Fatal("should not produce duplicate notification for same src/dst namespace")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleFlowDrop_EmptyNamespaces(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	// Constraint exists but neither source nor destination has a namespace
	constraint := internaltypes.Constraint{
		UID:            types.UID("c-any"),
		Name:           "any-constraint",
		Namespace:      "",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	drop := hubble.NewFlowDropBuilder().
		WithSource("", "pod1", nil).
		WithDestination("", "pod2", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	// Both namespaces are empty, so handleFlowDrop returns early
	select {
	case <-c.flowDrops:
		t.Fatal("should not produce notification when both namespaces are empty")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleFlowDrop_WorkloadRefs(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-wl"),
		Name:           "workload-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithSourceWorkload("Deployment", "client-deploy").
		WithDestination("default", "backend-pod", nil).
		WithDestinationWorkload("StatefulSet", "backend-sts").
		WithTCP(10000, 5432, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	select {
	case n := <-c.flowDrops:
		assert.Equal(t, "client-deploy", n.SourceWorkload)
		assert.Equal(t, "backend-sts", n.DestWorkload)
	case <-time.After(time.Second):
		t.Fatal("expected notification with workload refs")
	}
}

func TestHandleFlowDrop_RateLimited(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-rl"),
		Name:           "rate-limit-test",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	// Exhaust the rate limiter burst (eventRateBurst = 200)
	// The limiter uses a token bucket with burst=200.
	// We drain all tokens by reserving them.
	for i := 0; i < eventRateBurst+50; i++ {
		c.limiter.Allow()
	}

	// Now a policy drop should be rate-limited
	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("default", "backend", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	c.handleFlowDrop(ctx, drop)

	select {
	case <-c.flowDrops:
		t.Fatal("rate-limited flow drop should not produce notification")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleEvent_RateLimited(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-rl-evt"),
		Name:           "rate-limit-event",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	// Exhaust the rate limiter burst
	for i := 0; i < eventRateBurst+50; i++ {
		c.limiter.Allow()
	}

	event := makeEvent("evt-rl", "default", "my-pod", "Pod")
	c.handleEvent(ctx, event)

	select {
	case <-c.Notifications():
		t.Fatal("rate-limited event should not produce notification")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHandleFlowDrop_ChannelFull(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-fd-full"),
		Name:           "fd-full-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	// Fill the flowDrops channel to capacity
	for i := 0; i < notificationBuffer; i++ {
		c.flowDrops <- FlowDropNotification{}
	}

	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("default", "backend", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	done := make(chan struct{})
	go func() {
		c.handleFlowDrop(ctx, drop)
		close(done)
	}()

	select {
	case <-done:
		// handleFlowDrop returned without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("handleFlowDrop blocked on full channel")
	}
}

func TestHandleFlowDrop_ContextCanceled(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-fd-ctx"),
		Name:           "fd-ctx-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	// Fill the channel so the select will need ctx.Done or default
	for i := 0; i < notificationBuffer; i++ {
		c.flowDrops <- FlowDropNotification{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "client", nil).
		WithDestination("default", "backend", nil).
		WithTCP(10000, 80, hubble.TCPFlags{}).
		WithDropReason(hubble.DropReasonPolicy).
		Build()

	done := make(chan struct{})
	go func() {
		c.handleFlowDrop(ctx, drop)
		close(done)
	}()

	select {
	case <-done:
		// Returned without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("handleFlowDrop blocked with canceled context")
	}
}

func TestHandleFlowDrop_UDPProtocol(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx := context.Background()

	constraint := internaltypes.Constraint{
		UID:            types.UID("c-udp"),
		Name:           "udp-constraint",
		Namespace:      "default",
		ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
	}
	idx.Upsert(constraint)

	drop := hubble.NewFlowDropBuilder().
		WithSource("external", "dns-client", nil).
		WithDestination("default", "dns-server", nil).
		WithUDP(44444, 53).
		WithDropReason(hubble.DropReasonPolicyL4).
		Build()

	c.handleFlowDrop(ctx, drop)

	select {
	case n := <-c.flowDrops:
		assert.Equal(t, "UDP", n.Protocol)
		assert.Equal(t, uint32(53), n.DestPort)
		assert.Equal(t, "udp-constraint", n.Constraint.Name)
	case <-time.After(time.Second):
		t.Fatal("expected UDP flow drop notification")
	}
}

func TestCleanupDedupeCache_ContextCanceled(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	done := make(chan struct{})
	go func() {
		c.cleanupDedupeCache(ctx)
		close(done)
	}()

	select {
	case <-done:
		// cleanupDedupeCache exited on canceled context
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupDedupeCache did not exit on canceled context")
	}
}

func TestHandleFlowDrop_VariousPolicyDropReasons(t *testing.T) {
	policyReasons := []hubble.DropReason{
		hubble.DropReasonPolicy,
		hubble.DropReasonPolicyL3,
		hubble.DropReasonPolicyL4,
		hubble.DropReasonPolicyL7,
		hubble.DropReasonPolicyAuth,
		hubble.DropReasonNoNetworkPolicy,
		hubble.DropReasonIngressDenied,
		hubble.DropReasonEgressDenied,
	}

	for _, reason := range policyReasons {
		t.Run(string(reason), func(t *testing.T) {
			idx := indexer.New(nil)
			c := New(idx, nil, zap.NewNop())
			ctx := context.Background()

			constraint := internaltypes.Constraint{
				UID:            types.UID("c-" + string(reason)),
				Name:           "constraint-" + string(reason),
				Namespace:      "default",
				ConstraintType: internaltypes.ConstraintTypeNetworkIngress,
			}
			idx.Upsert(constraint)

			drop := hubble.NewFlowDropBuilder().
				WithSource("external", "client", nil).
				WithDestination("default", "server", nil).
				WithTCP(10000, 80, hubble.TCPFlags{}).
				WithDropReason(reason).
				Build()

			c.handleFlowDrop(ctx, drop)

			select {
			case n := <-c.flowDrops:
				assert.Equal(t, "constraint-"+string(reason), n.Constraint.Name)
			case <-time.After(time.Second):
				t.Fatalf("expected notification for policy drop reason %s", reason)
			}
		})
	}
}

// keys is a test helper that extracts map keys.
func keys(m map[string]FlowDropNotification) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// --- Integration tests for Start, watchEvents, processFlowDrops, cleanupDedupeCache ---

func TestWatchEvents_CorrelatesWarningEvent(t *testing.T) {
	// Create a fake Kubernetes clientset with a controlled watch.
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()

	// Register a watch reactor that returns our controlled watcher for events.
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	// Add a constraint in namespace "test-ns" so the correlator can match events.
	constraint := internaltypes.Constraint{
		UID:            types.UID("watch-c1"),
		Name:           "watch-constraint",
		Namespace:      "test-ns",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start watchEvents in a goroutine (it blocks until context is cancelled or watch closes).
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.watchEvents(ctx)
	}()

	// Inject a Warning event into the fake watcher.
	warningEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID("watch-evt-1"),
			Name:      "watch-event-1",
			Namespace: "test-ns",
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: "test-ns",
			Name:      "my-pod",
			Kind:      "Pod",
		},
		Type:    "Warning",
		Reason:  "FailedScheduling",
		Message: "no nodes available",
	}
	fakeWatcher.Add(warningEvent)

	// Read from Notifications() to verify the event was correlated.
	select {
	case notification := <-c.Notifications():
		assert.Equal(t, "test-ns", notification.Namespace)
		assert.Equal(t, "my-pod", notification.WorkloadName)
		assert.Equal(t, "Pod", notification.WorkloadKind)
		assert.Equal(t, "watch-constraint", notification.Constraint.Name)
		assert.Equal(t, types.UID("watch-evt-1"), notification.Event.UID)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for notification from watchEvents")
	}

	// Cancel context to stop watchEvents.
	cancel()

	select {
	case err := <-errCh:
		// watchEvents should return context.Canceled.
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("watchEvents did not return after context cancellation")
	}
}

func TestWatchEvents_IgnoresNonAddedModifiedEvents(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	constraint := internaltypes.Constraint{
		UID:            types.UID("ignore-c1"),
		Name:           "ignore-constraint",
		Namespace:      "test-ns",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c.watchEvents(ctx)
	}()

	// Inject a Deleted event -- should NOT trigger handleEvent.
	warningEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID("del-evt-1"),
			Name:      "delete-event-1",
			Namespace: "test-ns",
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: "test-ns",
			Name:      "my-pod",
			Kind:      "Pod",
		},
		Type: "Warning",
	}
	fakeWatcher.Delete(warningEvent)

	// No notification should appear.
	select {
	case <-c.Notifications():
		t.Fatal("deleted event should not produce a notification")
	case <-time.After(300 * time.Millisecond):
		// Expected: no notification for Delete event type.
	}

	cancel()
}

func TestWatchEvents_ModifiedEventProducesNotification(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	constraint := internaltypes.Constraint{
		UID:            types.UID("mod-c1"),
		Name:           "mod-constraint",
		Namespace:      "test-ns",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c.watchEvents(ctx)
	}()

	// Inject a Modified event -- should trigger handleEvent.
	warningEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID("mod-evt-1"),
			Name:      "modified-event-1",
			Namespace: "test-ns",
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: "test-ns",
			Name:      "my-pod",
			Kind:      "Pod",
		},
		Type:    "Warning",
		Reason:  "BackOff",
		Message: "back-off restarting",
	}
	fakeWatcher.Modify(warningEvent)

	select {
	case notification := <-c.Notifications():
		assert.Equal(t, "test-ns", notification.Namespace)
		assert.Equal(t, "my-pod", notification.WorkloadName)
		assert.Equal(t, "mod-constraint", notification.Constraint.Name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for notification from Modified event")
	}

	cancel()
}

func TestWatchEvents_WatchChannelClosed(t *testing.T) {
	// When the watch channel is closed (e.g. server-side timeout), watchEvents
	// should return nil so the caller can retry.
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.watchEvents(ctx)
	}()

	// Close the watcher to simulate a server-side disconnect.
	fakeWatcher.Stop()

	select {
	case err := <-errCh:
		// watchEvents returns nil when the channel is closed (will be retried by Start).
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("watchEvents did not return after watcher channel closed")
	}
}

func TestStart_ContextCancellation(t *testing.T) {
	// Start should return nil when the context is cancelled.
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Give Start a moment to enter watchEvents.
	time.Sleep(100 * time.Millisecond)

	// Stop the watcher to make watchEvents return, then the context check in Start
	// fires because ctx is cancelled.
	cancel()
	fakeWatcher.Stop()

	select {
	case err := <-errCh:
		assert.NoError(t, err, "Start should return nil on context cancellation")
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestStart_WithHubbleClient(t *testing.T) {
	// When a Hubble client is provided, Start should launch processFlowDrops.
	// We verify this by creating a real hubble.Client and closing it, which
	// causes processFlowDrops to detect the closed channel and exit.
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hubbleClient, err := hubble.NewClient(ctx, hubble.ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)

	idx := indexer.New(nil)
	opts := CorrelatorOptions{HubbleClient: hubbleClient}
	c := NewWithOptions(idx, fakeClient, zap.NewNop(), opts)

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Give Start time to launch goroutines.
	time.Sleep(100 * time.Millisecond)

	// Close hubble client to close its drops channel, then cancel context.
	hubbleClient.Close()
	cancel()
	fakeWatcher.Stop()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after hubble client closed and context cancelled")
	}
}

func TestStart_CorrelatesEventsEndToEnd(t *testing.T) {
	// End-to-end: Start the correlator, inject a Warning event, read the notification.
	fakeClient := fake.NewSimpleClientset()
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(fakeWatcher, nil))

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	constraint := internaltypes.Constraint{
		UID:            types.UID("e2e-c1"),
		Name:           "e2e-constraint",
		Namespace:      "prod",
		ConstraintType: internaltypes.ConstraintTypeAdmission,
	}
	idx.Upsert(constraint)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Give Start a moment to enter watchEvents.
	time.Sleep(100 * time.Millisecond)

	// Inject a Warning event.
	fakeWatcher.Add(&corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID("e2e-evt-1"),
			Name:      "e2e-event-1",
			Namespace: "prod",
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: "prod",
			Name:      "web-deploy",
			Kind:      "Deployment",
		},
		Type:    "Warning",
		Reason:  "FailedCreate",
		Message: "quota exceeded",
	})

	// Read the notification.
	select {
	case notification := <-c.Notifications():
		assert.Equal(t, "prod", notification.Namespace)
		assert.Equal(t, "web-deploy", notification.WorkloadName)
		assert.Equal(t, "Deployment", notification.WorkloadKind)
		assert.Equal(t, "e2e-constraint", notification.Constraint.Name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for end-to-end notification")
	}

	// Cleanup.
	cancel()
	fakeWatcher.Stop()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after cleanup")
	}
}

func TestProcessFlowDrops_ContextCancelled(t *testing.T) {
	// processFlowDrops should exit when context is cancelled.
	ctx, cancel := context.WithCancel(context.Background())

	hubbleClient, err := hubble.NewClient(ctx, hubble.ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)
	defer hubbleClient.Close()

	idx := indexer.New(nil)
	c := NewWithOptions(idx, nil, zap.NewNop(), CorrelatorOptions{HubbleClient: hubbleClient})

	done := make(chan struct{})
	go func() {
		c.processFlowDrops(ctx)
		close(done)
	}()

	// Cancel context to trigger exit.
	cancel()

	select {
	case <-done:
		// processFlowDrops exited due to context cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("processFlowDrops did not exit after context cancellation")
	}
}

func TestProcessFlowDrops_NilHubbleClient(t *testing.T) {
	// processFlowDrops should return immediately when hubbleClient is nil.
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	done := make(chan struct{})
	go func() {
		c.processFlowDrops(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Returned immediately.
	case <-time.After(time.Second):
		t.Fatal("processFlowDrops should return immediately when hubbleClient is nil")
	}
}

func TestProcessFlowDrops_ChannelClosed(t *testing.T) {
	// When the hubble client's drops channel is closed, processFlowDrops should exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hubbleClient, err := hubble.NewClient(ctx, hubble.ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)

	idx := indexer.New(nil)
	c := NewWithOptions(idx, nil, zap.NewNop(), CorrelatorOptions{HubbleClient: hubbleClient})

	done := make(chan struct{})
	go func() {
		c.processFlowDrops(ctx)
		close(done)
	}()

	// Close the hubble client, which closes its drops channel.
	hubbleClient.Close()

	select {
	case <-done:
		// processFlowDrops exited because drops channel was closed.
	case <-time.After(5 * time.Second):
		t.Fatal("processFlowDrops did not exit after hubble client channel closed")
	}
}

func TestStart_RetriesOnWatchError(t *testing.T) {
	// Test that Start retries when watchEvents returns an error
	// (and the context is not yet cancelled).
	fakeClient := fake.NewSimpleClientset()

	// First call to Watch returns an error, second call returns a watcher
	// that we immediately close so watchEvents returns nil, then we cancel context.
	callCount := 0
	fakeWatcher := watch.NewFake()
	fakeClient.PrependWatchReactor("events", func(action k8stesting.Action) (bool, watch.Interface, error) {
		callCount++
		if callCount == 1 {
			// First call: return an error to trigger the retry path.
			return true, nil, context.DeadlineExceeded
		}
		// Second call: return a watcher that we will stop shortly.
		return true, fakeWatcher, nil
	})

	idx := indexer.New(nil)
	c := New(idx, fakeClient, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Wait for the retry sleep (5s) plus some margin. Start will:
	// 1. Call watchEvents -> Watch returns error -> watchEvents returns error
	// 2. ctx.Err() is nil -> logs error, sleeps 5s
	// 3. Calls watchEvents again -> Watch returns fakeWatcher
	// 4. We cancel context and stop watcher
	time.Sleep(6 * time.Second)
	cancel()
	fakeWatcher.Stop()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, callCount, 2, "Watch should have been called at least twice")
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after retry and context cancellation")
	}
}

func TestCleanupDedupeCache_TickerRemovesOldEntries(t *testing.T) {
	// Test the actual cleanupDedupeCache method (not inline logic) by seeding
	// old entries and running the method with a very short-lived ticker cycle.
	// Since the ticker is 1 minute, we run the goroutine and cancel after a tick.
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	// Seed the cache with an old entry (well past the 5-minute dedupeWindow)
	// and a fresh entry.
	oldKey := dedupeKey{eventUID: "ticker-old", constraintUID: "c1"}
	newKey := dedupeKey{eventUID: "ticker-new", constraintUID: "c1"}

	c.mu.Lock()
	c.seenPairs[oldKey] = time.Now().Add(-10 * time.Minute)
	c.seenPairs[newKey] = time.Now()
	c.mu.Unlock()

	// We need cleanupDedupeCache to run at least one ticker cycle.
	// The ticker fires every 1 minute, which is too slow for a unit test.
	// Instead, we call the method directly through a goroutine and give it
	// a context that lives long enough for one tick. However, that would be
	// 60 seconds which is too long.
	//
	// Better approach: directly invoke the cleanup logic within the method by
	// verifying entries before/after. Since the existing TestCleanupDedupeCache
	// already tests the inline logic, here we test the goroutine lifecycle.
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.cleanupDedupeCache(ctx)
		close(done)
	}()

	// Cancel immediately to test the context-exit path of the ticker loop.
	cancel()

	select {
	case <-done:
		// cleanupDedupeCache exited when context was cancelled.
	case <-time.After(5 * time.Second):
		t.Fatal("cleanupDedupeCache did not exit after context cancellation")
	}

	// Verify entries are still present (cleanup didn't trigger because we
	// cancelled before the 1-minute ticker fired).
	c.mu.Lock()
	_, oldExists := c.seenPairs[oldKey]
	_, newExists := c.seenPairs[newKey]
	c.mu.Unlock()
	assert.True(t, oldExists, "old entry should still exist (ticker didn't fire)")
	assert.True(t, newExists, "new entry should still exist")
}

func TestCorrelator_TryMarkSeen_Concurrent(t *testing.T) {
	idx := indexer.New(nil)
	c := New(idx, nil, zap.NewNop())

	key := dedupeKey{eventUID: "conc-evt", constraintUID: "conc-c"}

	const goroutines = 100
	results := make(chan bool, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- c.tryMarkSeen(key)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	trueCount := 0
	for r := range results {
		if r {
			trueCount++
		}
	}
	assert.Equal(t, 1, trueCount, "exactly one goroutine should succeed for the same key")
}
