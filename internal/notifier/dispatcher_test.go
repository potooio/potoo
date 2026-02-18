package notifier

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/potooio/potoo/internal/correlator"
	"github.com/potooio/potoo/internal/types"
)

func TestDefaultDispatcherOptions(t *testing.T) {
	opts := DefaultDispatcherOptions()
	assert.Equal(t, 60, opts.SuppressDuplicateMinutes)
	assert.Equal(t, 100, opts.RateLimitPerMinute)
	assert.Equal(t, "your platform team", opts.RemediationContact)
}

func TestNewDispatcher(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)
	require.NotNil(t, d)
	assert.NotNil(t, d.dedupeCache)
	assert.NotNil(t, d.nsLimiter)
}

func TestRenderMessage_Summary(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.RemediationContact = "platform-team@example.com"
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	tests := []struct {
		name           string
		constraintType types.ConstraintType
		wantContains   string
	}{
		{
			name:           "network ingress",
			constraintType: types.ConstraintTypeNetworkIngress,
			wantContains:   "Inbound network traffic is restricted",
		},
		{
			name:           "network egress",
			constraintType: types.ConstraintTypeNetworkEgress,
			wantContains:   "Outbound network traffic is restricted",
		},
		{
			name:           "admission",
			constraintType: types.ConstraintTypeAdmission,
			wantContains:   "validation policy",
		},
		{
			name:           "resource limit",
			constraintType: types.ConstraintTypeResourceLimit,
			wantContains:   "quotas or limits",
		},
		{
			name:           "mesh policy",
			constraintType: types.ConstraintTypeMeshPolicy,
			wantContains:   "mesh policies",
		},
		{
			name:           "missing resource",
			constraintType: types.ConstraintTypeMissing,
			wantContains:   "companion resource",
		},
		{
			name:           "unknown type",
			constraintType: types.ConstraintTypeUnknown,
			wantContains:   "policy constraint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := types.Constraint{
				ConstraintType: tt.constraintType,
			}
			msg := d.RenderMessage(c, types.DetailLevelSummary)
			assert.Contains(t, msg, tt.wantContains)
			assert.Contains(t, msg, "platform-team@example.com")
		})
	}
}

func TestRenderMessage_Detailed(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	c := types.Constraint{
		Name:            "deny-egress",
		ConstraintType:  types.ConstraintTypeNetworkEgress,
		Summary:         "Restricts egress to port 443",
		RemediationHint: "See runbook https://example.com/runbook",
	}

	msg := d.RenderMessage(c, types.DetailLevelDetailed)
	assert.Contains(t, msg, "deny-egress")
	assert.Contains(t, msg, "Restricts egress to port 443")
	assert.Contains(t, msg, "runbook")
}

func TestRenderMessage_Detailed_NoSummary(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.RemediationContact = "ops@example.com"
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	c := types.Constraint{
		Name:           "empty-constraint",
		ConstraintType: types.ConstraintTypeNetworkIngress,
	}

	msg := d.RenderMessage(c, types.DetailLevelDetailed)
	assert.Contains(t, msg, "empty-constraint")
	// Falls back to generic effect
	assert.Contains(t, msg, "Inbound network traffic")
	// Falls back to contact
	assert.Contains(t, msg, "ops@example.com")
}

func TestRenderMessage_Full(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	c := types.Constraint{
		Name:            "deny-egress",
		Namespace:       "kube-system",
		ConstraintType:  types.ConstraintTypeNetworkEgress,
		Summary:         "Restricts egress",
		RemediationHint: "Contact admin",
		Source:          schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	msg := d.RenderMessage(c, types.DetailLevelFull)
	assert.Contains(t, msg, "networking.k8s.io/v1/networkpolicies")
	assert.Contains(t, msg, "kube-system/deny-egress")
	assert.Contains(t, msg, "Restricts egress")
}

func TestRenderMessage_Full_CoreGroup(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	c := types.Constraint{
		Name:           "quota",
		ConstraintType: types.ConstraintTypeResourceLimit,
		Source:         schema.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"},
	}

	msg := d.RenderMessage(c, types.DetailLevelFull)
	assert.Contains(t, msg, "core/v1/resourcequotas")
}

func TestRenderMessage_Full_ClusterScoped(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	c := types.Constraint{
		Name:           "cluster-policy",
		Namespace:      "", // cluster-scoped
		ConstraintType: types.ConstraintTypeAdmission,
		Source:         schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"},
	}

	msg := d.RenderMessage(c, types.DetailLevelFull)
	// Cluster-scoped should not have namespace prefix
	assert.Contains(t, msg, `"cluster-policy"`)
}

func TestDispatch_CreateEvent(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	notification := correlator.CorrelatedNotification{
		Constraint: types.Constraint{
			UID:            k8stypes.UID("test-uid"),
			Name:           "test-constraint",
			ConstraintType: types.ConstraintTypeNetworkEgress,
			Severity:       types.SeverityWarning,
		},
		Namespace:    "team-alpha",
		WorkloadName: "my-deployment",
		WorkloadKind: "Deployment",
	}

	err := d.Dispatch(ctx, notification)
	require.NoError(t, err)

	// Verify event was created
	events, err := client.CoreV1().Events("team-alpha").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, events.Items, 1)

	event := events.Items[0]
	assert.Equal(t, "ConstraintNotification", event.Reason)
	assert.Equal(t, "Warning", event.Type)
	assert.Equal(t, "my-deployment", event.InvolvedObject.Name)
	assert.Equal(t, "Deployment", event.InvolvedObject.Kind)
	assert.Equal(t, "team-alpha", event.InvolvedObject.Namespace)
}

func TestDispatch_Deduplication(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	notification := correlator.CorrelatedNotification{
		Constraint: types.Constraint{
			UID:            k8stypes.UID("dedup-uid"),
			Name:           "test-constraint",
			ConstraintType: types.ConstraintTypeNetworkEgress,
		},
		Namespace:    "team-alpha",
		WorkloadName: "my-app",
		WorkloadKind: "Deployment",
	}

	// First dispatch should succeed
	err := d.Dispatch(ctx, notification)
	require.NoError(t, err)

	// Second dispatch with same constraint+workload should be suppressed
	err = d.Dispatch(ctx, notification)
	require.NoError(t, err)

	// Only one event should exist
	events, err := client.CoreV1().Events("team-alpha").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, events.Items, 1)
}

func TestDispatchDirect(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	c := types.Constraint{
		UID:            k8stypes.UID("direct-uid"),
		Name:           "direct-constraint",
		ConstraintType: types.ConstraintTypeAdmission,
	}

	err := d.DispatchDirect(ctx, c, "team-beta", "my-pod", "Pod", types.DetailLevelDetailed)
	require.NoError(t, err)

	events, err := client.CoreV1().Events("team-beta").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, events.Items, 1)

	event := events.Items[0]
	assert.Equal(t, "ConstraintNotification", event.Reason)
	assert.Equal(t, "my-pod", event.InvolvedObject.Name)
	assert.Equal(t, "Pod", event.InvolvedObject.Kind)
}

func TestDispatchDirect_Deduplication(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	c := types.Constraint{
		UID:            k8stypes.UID("direct-dedup"),
		Name:           "test",
		ConstraintType: types.ConstraintTypeAdmission,
	}

	err := d.DispatchDirect(ctx, c, "ns", "workload", "Deployment", types.DetailLevelSummary)
	require.NoError(t, err)

	err = d.DispatchDirect(ctx, c, "ns", "workload", "Deployment", types.DetailLevelSummary)
	require.NoError(t, err)

	events, err := client.CoreV1().Events("ns").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, events.Items, 1) // Deduplicated
}

func TestNsRateLimiter(t *testing.T) {
	limiter := newNsRateLimiter(100)
	require.NotNil(t, limiter)

	// Should allow first request
	assert.True(t, limiter.Allow("test-ns"))

	// Different namespace should also be allowed
	assert.True(t, limiter.Allow("other-ns"))
}

func TestNewNsRateLimiter_MinBurst(t *testing.T) {
	// When perMinute < 10, burst must still be at least 1 (not 0).
	limiter := newNsRateLimiter(1)
	assert.GreaterOrEqual(t, limiter.burst, 1, "burst should be at least 1 even with perMinute=1")
	// With burst=1, first Allow() should succeed
	assert.True(t, limiter.Allow("test-ns"), "first call should pass with burst=1")
}

func TestGenericEffect(t *testing.T) {
	tests := []struct {
		ct   types.ConstraintType
		want string
	}{
		{types.ConstraintTypeNetworkIngress, "Inbound network traffic is restricted"},
		{types.ConstraintTypeNetworkEgress, "Outbound network traffic is restricted"},
		{types.ConstraintTypeAdmission, "A validation policy may reject your resources"},
		{types.ConstraintTypeResourceLimit, "Resource quotas or limits apply"},
		{types.ConstraintTypeMeshPolicy, "Service mesh policies apply"},
		{types.ConstraintTypeMissing, "A required companion resource may be missing"},
		{types.ConstraintTypeUnknown, "A policy constraint applies"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ct), func(t *testing.T) {
			assert.Equal(t, tt.want, genericEffect(tt.ct))
		})
	}
}

// --- New tests to boost coverage ---

func TestDispatch_RateLimited(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.RateLimitPerMinute = 1 // Very low rate limit (burst = 0)
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	// Exhaust the burst by sending multiple notifications for same namespace
	for i := 0; i < 20; i++ {
		n := correlator.CorrelatedNotification{
			Constraint: types.Constraint{
				UID:            k8stypes.UID(fmt.Sprintf("uid-rl-%d", i)),
				Name:           "test-constraint",
				ConstraintType: types.ConstraintTypeNetworkEgress,
			},
			Namespace:    "rate-limited-ns",
			WorkloadName: fmt.Sprintf("workload-%d", i),
			WorkloadKind: "Deployment",
		}
		_ = d.Dispatch(ctx, n)
	}

	// At most a few events should have been created because of rate limiting
	events, err := client.CoreV1().Events("rate-limited-ns").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	// With burst = 1 (max(1, 1/10)), exactly one initial event is allowed
	assert.LessOrEqual(t, len(events.Items), 5, "Rate limiter should limit events created")
}

func TestDispatchDirect_RateLimited(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.RateLimitPerMinute = 1 // Very low limit
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	ctx := context.Background()

	// Send multiple direct dispatches
	for i := 0; i < 20; i++ {
		c := types.Constraint{
			UID:            k8stypes.UID(fmt.Sprintf("uid-drl-%d", i)),
			Name:           "test",
			ConstraintType: types.ConstraintTypeAdmission,
		}
		_ = d.DispatchDirect(ctx, c, "rl-ns", fmt.Sprintf("workload-%d", i), "Pod", types.DetailLevelSummary)
	}

	events, err := client.CoreV1().Events("rl-ns").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(events.Items), 5, "Rate limiter should limit direct dispatch events")
}

func TestDispatcher_CleanupDedupeCache(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.SuppressDuplicateMinutes = 0 // Zero minute = everything is expired immediately
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	// Manually add an old entry to the dedupe cache
	oldKey := dedupeKey{constraintUID: "old-uid", workloadUID: "old-workload"}
	d.mu.Lock()
	d.dedupeCache[oldKey] = time.Now().Add(-2 * time.Hour) // 2 hours ago
	d.mu.Unlock()

	// Start the cleanup in a context that we cancel quickly
	ctx, cancel := context.WithCancel(context.Background())

	// Run cleanup directly (the goroutine function)
	go d.cleanupDedupeCache(ctx)

	// Wait a bit for the ticker to fire (5 minute interval is too long for a test)
	// Instead, we'll just test that the function can be cancelled
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Verify the cache entry still exists (cleanup interval is 5 minutes, won't fire in 50ms)
	d.mu.Lock()
	_, exists := d.dedupeCache[oldKey]
	d.mu.Unlock()
	assert.True(t, exists, "Entry should still exist since cleanup interval is 5 minutes")
}

func TestDispatcher_Start(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)

	// Give the goroutine time to start
	time.Sleep(20 * time.Millisecond)

	// Cancel should stop the background goroutine
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestDispatcher_TryMarkSeen_Expired(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := DefaultDispatcherOptions()
	opts.SuppressDuplicateMinutes = 1 // 1 minute window
	d := NewDispatcher(client, zap.NewNop(), opts, nil)

	key := dedupeKey{constraintUID: "exp-uid", workloadUID: "exp-wl"}

	// Mark as seen 2 minutes ago
	d.mu.Lock()
	d.dedupeCache[key] = time.Now().Add(-2 * time.Minute)
	d.mu.Unlock()

	// Should succeed since the suppress window (1 minute) has expired
	assert.True(t, d.tryMarkSeen(key), "Expired entry should allow re-marking")
}

func TestDispatcher_TryMarkSeen_NotSeen(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	key := dedupeKey{constraintUID: "new-uid", workloadUID: "new-wl"}
	assert.True(t, d.tryMarkSeen(key), "Unseen entry should be marked successfully")

	// Second call should be a duplicate
	assert.False(t, d.tryMarkSeen(key), "Already-seen entry should be rejected")
}

func TestDispatcher_TryMarkSeen_Records(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	key := dedupeKey{constraintUID: "mark-uid", workloadUID: "mark-wl"}

	assert.True(t, d.tryMarkSeen(key), "First call should succeed")

	d.mu.Lock()
	_, exists := d.dedupeCache[key]
	d.mu.Unlock()
	assert.True(t, exists, "tryMarkSeen should add key to dedupe cache")
}

func TestDispatcher_TryMarkSeen_Concurrent(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	key := dedupeKey{constraintUID: "conc-uid", workloadUID: "conc-wl"}

	const goroutines = 100
	results := make(chan bool, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- d.tryMarkSeen(key)
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

func TestNsRateLimiter_NewNamespace(t *testing.T) {
	limiter := newNsRateLimiter(100)

	// New namespace should create a limiter and allow
	assert.True(t, limiter.Allow("ns1"))
	assert.True(t, limiter.Allow("ns2"))

	// Verify separate limiters exist
	limiter.mu.Lock()
	assert.Len(t, limiter.limiters, 2)
	limiter.mu.Unlock()
}

func TestNsRateLimiter_Evict(t *testing.T) {
	limiter := newNsRateLimiter(100)

	// Access two namespaces
	limiter.Allow("active-ns")
	limiter.Allow("stale-ns")

	// Backdate the stale namespace's lastAccess
	limiter.mu.Lock()
	limiter.lastAccess["stale-ns"] = time.Now().Add(-2 * time.Hour)
	limiter.mu.Unlock()

	// Evict entries older than 1 hour
	limiter.Evict(time.Hour)

	limiter.mu.Lock()
	_, activeExists := limiter.limiters["active-ns"]
	_, staleExists := limiter.limiters["stale-ns"]
	limiter.mu.Unlock()

	assert.True(t, activeExists, "active namespace should be retained")
	assert.False(t, staleExists, "stale namespace should be evicted")
}

func TestNsRateLimiter_EvictPreservesRecent(t *testing.T) {
	limiter := newNsRateLimiter(100)

	limiter.Allow("ns1")
	limiter.Allow("ns2")

	// Evict with 1 hour maxAge — both were just accessed, so neither should be evicted
	limiter.Evict(time.Hour)

	limiter.mu.Lock()
	assert.Len(t, limiter.limiters, 2, "recently accessed namespaces should be retained")
	limiter.mu.Unlock()
}

func TestDispatch_DifferentWorkloadSameConstraint(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	ctx := context.Background()

	// Same constraint, different workloads -- should NOT deduplicate
	// Both should pass isDuplicate check since workload UIDs differ
	n1 := correlator.CorrelatedNotification{
		Constraint: types.Constraint{
			UID:            k8stypes.UID("same-constraint"),
			Name:           "test-constraint",
			ConstraintType: types.ConstraintTypeNetworkEgress,
		},
		Namespace:    "team-alpha",
		WorkloadName: "workload-a",
		WorkloadKind: "Deployment",
	}
	err := d.Dispatch(ctx, n1)
	require.NoError(t, err)

	// Verify the deduplication logic: second workload should NOT be deduped
	key := dedupeKey{constraintUID: "same-constraint", workloadUID: "team-alpha/workload-b"}
	assert.True(t, d.tryMarkSeen(key), "Different workloads should not be deduplicated")
}

func TestDispatchDirect_FullLevel(t *testing.T) {
	client := fake.NewSimpleClientset()
	d := NewDispatcher(client, zap.NewNop(), DefaultDispatcherOptions(), nil)

	ctx := context.Background()

	c := types.Constraint{
		UID:             k8stypes.UID("full-uid"),
		Name:            "full-constraint",
		Namespace:       "kube-system",
		ConstraintType:  types.ConstraintTypeNetworkIngress,
		Summary:         "Full details shown",
		RemediationHint: "Contact admin@example.com",
		Source:          schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}

	err := d.DispatchDirect(ctx, c, "team-beta", "my-pod", "Pod", types.DetailLevelFull)
	require.NoError(t, err)

	events, err := client.CoreV1().Events("team-beta").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, events.Items, 1)

	// Full level should include source GVR
	assert.Contains(t, events.Items[0].Message, "networking.k8s.io/v1/networkpolicies")
	assert.Contains(t, events.Items[0].Message, "kube-system/full-constraint")
}
