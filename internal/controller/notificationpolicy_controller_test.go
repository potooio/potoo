package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/notifier"
	"github.com/potooio/potoo/internal/types"
)

func setupNotificationPolicyReconciler(t *testing.T, objs ...runtime.Object) (*NotificationPolicyReconciler, *notifier.PolicyRouter) {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(s))
	require.NoError(t, corev1.AddToScheme(s))

	clientBuilder := fake.NewClientBuilder().WithScheme(s)
	for _, obj := range objs {
		clientBuilder = clientBuilder.WithRuntimeObjects(obj)
	}
	c := clientBuilder.Build()

	pr := notifier.NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pr.SetContext(ctx)

	r := &NotificationPolicyReconciler{
		Client:       c,
		Logger:       zap.NewNop(),
		PolicyRouter: pr,
	}

	return r, pr
}

func TestNotificationPolicy_Reconcile_SinglePolicy(t *testing.T) {
	policy := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{
				MaxDetailLevel: "detailed",
				Contact:        "team@example.com",
			},
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: true,
					URL:     "http://example.com/hook",
				},
			},
		},
	}

	r, pr := setupNotificationPolicyReconciler(t, policy)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// PolicyRouter should have the policy.
	policies := pr.Policies()
	require.Len(t, policies, 1)
	assert.Equal(t, "default", policies[0].Name)

	// Detail level should be from the policy.
	assert.Equal(t, types.DetailLevelDetailed, pr.DetailLevel(types.DetailLevelSummary))

	// Contact should be from the policy.
	assert.Equal(t, "team@example.com", pr.Contact())

	// Should have one webhook sender.
	senders := pr.SendersForPolicies()
	require.Len(t, senders, 1)
	assert.Equal(t, "webhook", senders[0].Name())
}

func TestNotificationPolicy_Reconcile_MultiplePolicies(t *testing.T) {
	policy1 := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{MaxDetailLevel: "summary"},
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: true,
					URL:     "http://alpha.example.com/hook",
				},
			},
		},
	}
	policy2 := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bravo"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{MaxDetailLevel: "detailed"},
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled:     true,
					URL:         "http://bravo.example.com/hook",
					MinSeverity: "Critical",
				},
			},
		},
	}

	r, pr := setupNotificationPolicyReconciler(t, policy1, policy2)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "alpha"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Both policies should be present, sorted alphabetically.
	policies := pr.Policies()
	require.Len(t, policies, 2)
	assert.Equal(t, "alpha", policies[0].Name)
	assert.Equal(t, "bravo", policies[1].Name)

	// Two webhook senders.
	senders := pr.SendersForPolicies()
	assert.Len(t, senders, 2)
}

func TestNotificationPolicy_Reconcile_Deletion(t *testing.T) {
	// No policies in the cluster — simulates all deleted.
	r, pr := setupNotificationPolicyReconciler(t)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "deleted"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// PolicyRouter should be empty.
	assert.Empty(t, pr.Policies())
	assert.Nil(t, pr.SendersForPolicies())
}

func TestNotificationPolicy_Reconcile_AuthSecret(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "potoo-system")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-token",
			Namespace: "potoo-system",
		},
		Data: map[string][]byte{
			"token": []byte("secret-bearer-token"),
		},
	}

	policy := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "with-auth"},
		Spec: v1alpha1.NotificationPolicySpec{
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: true,
					URL:     "http://example.com/hook",
					AuthSecretRef: &v1alpha1.SecretKeyReference{
						Name: "webhook-token",
						Key:  "token",
					},
				},
			},
		},
	}

	r, pr := setupNotificationPolicyReconciler(t, secret, policy)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "with-auth"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Sender should have the auth token.
	senders := pr.SendersForPolicies()
	require.Len(t, senders, 1)
}

func TestNotificationPolicy_Reconcile_MissingSecret(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "potoo-system")

	policy := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-secret"},
		Spec: v1alpha1.NotificationPolicySpec{
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: true,
					URL:     "http://example.com/hook",
					AuthSecretRef: &v1alpha1.SecretKeyReference{
						Name: "does-not-exist",
						Key:  "token",
					},
				},
			},
		},
	}

	r, pr := setupNotificationPolicyReconciler(t, policy)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "missing-secret"},
	})
	// Should not error — missing secrets are logged as warnings, not failures.
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Sender should still be created (without auth token).
	senders := pr.SendersForPolicies()
	assert.Len(t, senders, 1)
}

func TestNotificationPolicy_Reconcile_NoChannels(t *testing.T) {
	policy := &v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "detail-only"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{
				MaxDetailLevel: "full",
			},
		},
	}

	r, pr := setupNotificationPolicyReconciler(t, policy)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Name: "detail-only"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Policy should be stored (detail level works even without channels).
	assert.Equal(t, types.DetailLevelFull, pr.DetailLevel(types.DetailLevelSummary))
	assert.Nil(t, pr.SendersForPolicies())
}

func TestControllerNamespace_EnvVar(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "custom-ns")
	assert.Equal(t, "custom-ns", controllerNamespace())
}

func TestControllerNamespace_Default(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	assert.Equal(t, "potoo-system", controllerNamespace())
}
