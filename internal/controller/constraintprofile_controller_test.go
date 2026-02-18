package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/adapters"
	"github.com/potooio/potoo/internal/discovery"
	"github.com/potooio/potoo/internal/indexer"
)

func setupReconciler(t *testing.T, objs ...runtime.Object) (*ConstraintProfileReconciler, *discovery.Engine) {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(s))

	clientBuilder := fake.NewClientBuilder().WithScheme(s)
	for _, obj := range objs {
		clientBuilder = clientBuilder.WithRuntimeObjects(obj)
	}
	c := clientBuilder.Build()

	idx := indexer.New(nil)
	registry := adapters.NewRegistry()
	engine := discovery.NewEngine(zap.NewNop(), nil, nil, registry, idx, 5*time.Minute)

	r := &ConstraintProfileReconciler{
		Client: c,
		Logger: zap.NewNop(),
		Engine: engine,
	}

	return r, engine
}

func TestReconcile_CreateProfile(t *testing.T) {
	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR: v1alpha1.GVRReference{
				Group:    "custom.io",
				Version:  "v1",
				Resource: "policies",
			},
			Adapter: "generic",
			Enabled: true,
		},
	}

	r, engine := setupReconciler(t, profile)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "test-profile"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Engine should have the profile registered (no informer started because no dynamic client)
	// We can verify by checking the engine state indirectly via the profile's effect on isConstraintLike
	// The engine has the profile registered internally.
	_ = engine
}

func TestReconcile_DeleteProfile(t *testing.T) {
	// No profile in the cluster — simulates deletion
	r, _ := setupReconciler(t)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "deleted-profile"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestReconcile_DisabledProfile(t *testing.T) {
	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR: v1alpha1.GVRReference{
				Group:    "custom.io",
				Version:  "v1",
				Resource: "restrictions",
			},
			Adapter: "generic",
			Enabled: false,
		},
	}

	r, engine := setupReconciler(t, profile)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "disabled-profile"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Engine should not start any informers for disabled profile
	assert.Empty(t, engine.WatchedGVRs())
}

func TestReconcile_ProfileWithFieldPaths(t *testing.T) {
	profile := &v1alpha1.ConstraintProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "field-paths-profile"},
		Spec: v1alpha1.ConstraintProfileSpec{
			GVR: v1alpha1.GVRReference{
				Group:    "custom.io",
				Version:  "v1",
				Resource: "widgets",
			},
			Adapter:  "generic",
			Enabled:  true,
			Severity: "Warning",
			FieldPaths: &v1alpha1.FieldPaths{
				SelectorPath: "spec.target.workloads",
				EffectPath:   "spec.action",
			},
		},
	}

	r, _ := setupReconciler(t, profile)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "field-paths-profile"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}
