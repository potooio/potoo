package requirements

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/types"
)

// mockRule is a test RequirementRule that returns canned results.
type mockRule struct {
	name        string
	constraints []types.Constraint
	err         error
	callCount   atomic.Int32
}

func (m *mockRule) Name() string        { return m.name }
func (m *mockRule) Description() string { return "mock rule" }
func (m *mockRule) Evaluate(_ context.Context, _ *unstructured.Unstructured, _ types.RequirementEvalContext) ([]types.Constraint, error) {
	m.callCount.Add(1)
	return m.constraints, m.err
}

// mockEvalContext is a no-op RequirementEvalContext for evaluator tests.
type mockEvalContext struct{}

func (m *mockEvalContext) GetNamespace(_ context.Context, _ string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockEvalContext) ListByGVR(_ context.Context, _ schema.GroupVersionResource, _ string) ([]*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockEvalContext) FindMatchingResources(_ context.Context, _ schema.GroupVersionResource, _ string, _ map[string]string) ([]*unstructured.Unstructured, error) {
	return nil, nil
}

func makeWorkload(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
				"uid":       string(k8stypes.UID("test-uid-" + name)),
			},
		},
	}
}

func TestNewEvaluator(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)

	if eval == nil {
		t.Fatal("NewEvaluator returned nil")
	}
	if len(eval.rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(eval.rules))
	}
}

func TestRegisterRule(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)

	r := &mockRule{name: "test-rule"}
	eval.RegisterRule(r)

	if len(eval.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(eval.rules))
	}
	if eval.rules[0].Name() != "test-rule" {
		t.Fatalf("expected rule name test-rule, got %s", eval.rules[0].Name())
	}
}

func TestEvaluate_NoRules(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	workload := makeWorkload("my-app", "default")
	constraints, err := eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 0 {
		t.Fatalf("expected 0 constraints, got %d", len(constraints))
	}
}

func TestEvaluate_NilWorkload(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)

	constraints, err := eval.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if constraints != nil {
		t.Fatalf("expected nil, got %v", constraints)
	}
}

func TestEvaluate_RuleReturnsConstraints_NoDebouce(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	r := &mockRule{
		name: "test-rule",
		constraints: []types.Constraint{
			{UID: "c1", Name: "constraint-1", ConstraintType: types.ConstraintTypeMissing},
		},
	}
	eval.RegisterRule(r)

	workload := makeWorkload("my-app", "default")
	constraints, err := eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(constraints))
	}
	if constraints[0].Name != "constraint-1" {
		t.Fatalf("expected constraint-1, got %s", constraints[0].Name)
	}
}

func TestEvaluate_Debounce_SuppressesThenEmits(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(5 * time.Minute)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.SetClock(func() time.Time { return now })

	r := &mockRule{
		name: "test-rule",
		constraints: []types.Constraint{
			{UID: "c1", Name: "constraint-1", ConstraintType: types.ConstraintTypeMissing},
		},
	}
	eval.RegisterRule(r)
	workload := makeWorkload("my-app", "default")

	// First call: within debounce window, should suppress.
	constraints, err := eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 0 {
		t.Fatalf("expected 0 constraints (debounce active), got %d", len(constraints))
	}

	// Advance clock past debounce window.
	now = now.Add(6 * time.Minute)

	// Second call: past debounce window, should emit.
	constraints, err = eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 1 {
		t.Fatalf("expected 1 constraint (debounce elapsed), got %d", len(constraints))
	}
}

func TestEvaluate_Debounce_ClearsWhenResourceAppears(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(5 * time.Minute)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.SetClock(func() time.Time { return now })

	r := &mockRule{
		name: "test-rule",
		constraints: []types.Constraint{
			{UID: "c1", Name: "constraint-1"},
		},
	}
	eval.RegisterRule(r)
	workload := makeWorkload("my-app", "default")

	// First call: records first-seen.
	_, _ = eval.Evaluate(context.Background(), workload)

	// Resource appears: rule returns empty.
	r.constraints = nil
	_, _ = eval.Evaluate(context.Background(), workload)

	// Verify debounce entry cleared.
	eval.debounce.mu.RLock()
	_, exists := eval.debounce.entries["test-uid-my-app:test-rule"]
	eval.debounce.mu.RUnlock()

	if exists {
		t.Fatal("expected debounce entry to be cleared when resource appeared")
	}

	// Resource disappears again: should start fresh debounce.
	r.constraints = []types.Constraint{{UID: "c1", Name: "constraint-1"}}
	now = now.Add(1 * time.Minute)
	constraints, _ := eval.Evaluate(context.Background(), workload)
	if len(constraints) != 0 {
		t.Fatal("expected fresh debounce to suppress constraint")
	}
}

func TestEvaluate_RuleError_ContinuesOtherRules(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	failRule := &mockRule{
		name: "fail-rule",
		err:  context.DeadlineExceeded,
	}
	okRule := &mockRule{
		name: "ok-rule",
		constraints: []types.Constraint{
			{UID: "c1", Name: "ok-constraint"},
		},
	}
	eval.RegisterRule(failRule)
	eval.RegisterRule(okRule)

	workload := makeWorkload("my-app", "default")
	constraints, err := eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 1 {
		t.Fatalf("expected 1 constraint from ok-rule, got %d", len(constraints))
	}
}

func TestEvaluate_DoesNotMutateWorkload(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	r := &mockRule{
		name:        "test-rule",
		constraints: []types.Constraint{{UID: "c1"}},
	}
	eval.RegisterRule(r)

	workload := makeWorkload("my-app", "default")
	// Deep copy the object map for comparison.
	original := workload.DeepCopy()

	_, _ = eval.Evaluate(context.Background(), workload)

	if workload.GetName() != original.GetName() {
		t.Fatal("workload name was mutated")
	}
	if workload.GetNamespace() != original.GetNamespace() {
		t.Fatal("workload namespace was mutated")
	}
	if string(workload.GetUID()) != string(original.GetUID()) {
		t.Fatal("workload UID was mutated")
	}
}

func TestCleanupStaleEntries(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(5 * time.Minute)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.SetClock(func() time.Time { return now })

	// Seed entries: one recently seen, one stale (not seen for a long time).
	eval.debounce.mu.Lock()
	eval.debounce.entries["fresh-key"] = debounceEntry{
		firstSeen: now.Add(-1 * time.Minute),
		lastSeen:  now.Add(-1 * time.Minute),
	}
	eval.debounce.entries["stale-key"] = debounceEntry{
		firstSeen: now.Add(-15 * time.Minute),
		lastSeen:  now.Add(-15 * time.Minute), // > 2 * 5min
	}
	eval.debounce.mu.Unlock()

	eval.CleanupStaleEntries()

	eval.debounce.mu.RLock()
	_, hasFresh := eval.debounce.entries["fresh-key"]
	_, hasStale := eval.debounce.entries["stale-key"]
	eval.debounce.mu.RUnlock()

	if !hasFresh {
		t.Fatal("fresh entry should not have been cleaned up")
	}
	if hasStale {
		t.Fatal("stale entry should have been cleaned up")
	}
}

func TestCleanupStaleEntries_ActivelyDetectedNotEvicted(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(5 * time.Minute)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.SetClock(func() time.Time { return now })

	// Entry with old firstSeen but recent lastSeen should NOT be evicted.
	// This is the exact scenario that was broken before the lastSeen fix:
	// the resource has been continuously detected for longer than 2x debounce,
	// but the evaluator refreshes lastSeen on every detection cycle.
	eval.debounce.mu.Lock()
	eval.debounce.entries["active-key"] = debounceEntry{
		firstSeen: now.Add(-15 * time.Minute), // older than 2x debounce (10min)
		lastSeen:  now.Add(-1 * time.Minute),  // recently seen
	}
	eval.debounce.mu.Unlock()

	eval.CleanupStaleEntries()

	eval.debounce.mu.RLock()
	_, hasActive := eval.debounce.entries["active-key"]
	eval.debounce.mu.RUnlock()

	if !hasActive {
		t.Fatal("actively-detected entry should not have been evicted")
	}
}

func TestStartCleanup_StopsOnCancel(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(10 * time.Millisecond)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eval.SetClock(func() time.Time { return now })

	// Seed a stale entry.
	eval.debounce.mu.Lock()
	eval.debounce.entries["stale-key"] = debounceEntry{
		firstSeen: now.Add(-1 * time.Hour),
		lastSeen:  now.Add(-1 * time.Hour),
	}
	eval.debounce.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		eval.StartCleanup(ctx)
		close(done)
	}()

	// Wait for at least one cleanup tick.
	time.Sleep(50 * time.Millisecond)

	// Stale entry should have been cleaned.
	eval.debounce.mu.RLock()
	_, hasStale := eval.debounce.entries["stale-key"]
	eval.debounce.mu.RUnlock()
	if hasStale {
		t.Fatal("expected stale entry to be cleaned by StartCleanup")
	}

	// Cancel context and verify goroutine exits.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StartCleanup did not return after context cancel")
	}
}

func TestEvaluate_WorkloadWithoutUID(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	r := &mockRule{
		name: "test-rule",
		constraints: []types.Constraint{
			{UID: "c1", Name: "constraint-1", ConstraintType: types.ConstraintTypeMissing},
		},
	}
	eval.RegisterRule(r)

	// Create workload without a UID — should fall back to namespace/name.
	workload := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "my-app",
				"namespace": "default",
			},
		},
	}

	constraints, err := eval.Evaluate(context.Background(), workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(constraints))
	}
}

func TestEvaluate_ConcurrentSafety(t *testing.T) {
	logger := zaptest.NewLogger(t)
	idx := indexer.New(nil)
	eval := NewEvaluator(idx, &mockEvalContext{}, logger)
	eval.SetDebounceDuration(0)

	r := &mockRule{
		name:        "test-rule",
		constraints: []types.Constraint{{UID: "c1", Name: "constraint-1"}},
	}
	eval.RegisterRule(r)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			workload := makeWorkload("app", "default")
			workload.Object["metadata"].(map[string]interface{})["uid"] = k8stypes.UID("uid-" + string(rune('a'+i%26)))
			_, _ = eval.Evaluate(context.Background(), workload)
		}(i)
	}
	wg.Wait()

	// Also run cleanup concurrently.
	wg.Add(2)
	go func() {
		defer wg.Done()
		eval.CleanupStaleEntries()
	}()
	go func() {
		defer wg.Done()
		workload := makeWorkload("app", "default")
		_, _ = eval.Evaluate(context.Background(), workload)
	}()
	wg.Wait()
}
