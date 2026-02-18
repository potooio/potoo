package controller

import (
	"context"
	"os"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/notifier"
)

// NotificationPolicyReconciler reconciles NotificationPolicy resources.
// On create/update/delete, it lists all policies, resolves auth secrets,
// and updates the PolicyRouter so the dispatcher and report reconciler
// route notifications according to the active policies.
type NotificationPolicyReconciler struct {
	Client       client.Client
	Logger       *zap.Logger
	PolicyRouter *notifier.PolicyRouter
}

func (r *NotificationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Logger.With(zap.String("policy", req.Name))

	// List all NotificationPolicy resources.
	var policyList v1alpha1.NotificationPolicyList
	if err := r.Client.List(ctx, &policyList); err != nil {
		log.Error("Failed to list NotificationPolicies", zap.Error(err))
		return ctrl.Result{}, err
	}

	log.Info("Reconciling NotificationPolicies",
		zap.Int("count", len(policyList.Items)),
		zap.String("trigger", req.Name),
	)

	// Resolve auth tokens from secrets.
	authTokens := r.resolveAuthTokens(ctx, policyList.Items)

	// Update the policy router with all current policies.
	r.PolicyRouter.Update(policyList.Items, authTokens)

	return ctrl.Result{}, nil
}

// resolveAuthTokens reads auth tokens from K8s Secrets for policies with authSecretRef.
func (r *NotificationPolicyReconciler) resolveAuthTokens(ctx context.Context, policies []v1alpha1.NotificationPolicy) map[string]string {
	tokens := make(map[string]string)
	ns := controllerNamespace()

	for _, p := range policies {
		if p.Spec.Channels.Webhook == nil || p.Spec.Channels.Webhook.AuthSecretRef == nil {
			continue
		}
		ref := p.Spec.Channels.Webhook.AuthSecretRef

		var secret corev1.Secret
		key := k8stypes.NamespacedName{
			Namespace: ns,
			Name:      ref.Name,
		}
		if err := r.Client.Get(ctx, key, &secret); err != nil {
			if apierrors.IsNotFound(err) {
				r.Logger.Warn("Auth secret not found for NotificationPolicy; webhook will have no auth token",
					zap.String("policy", p.Name),
					zap.String("secret", ref.Name),
					zap.String("namespace", ns),
				)
			} else {
				r.Logger.Error("Failed to read auth secret for NotificationPolicy",
					zap.String("policy", p.Name),
					zap.Error(err),
				)
			}
			continue
		}

		tokenBytes, ok := secret.Data[ref.Key]
		if !ok {
			r.Logger.Warn("Auth secret key not found for NotificationPolicy",
				zap.String("policy", p.Name),
				zap.String("secret", ref.Name),
				zap.String("key", ref.Key),
			)
			continue
		}

		tokens[p.Name] = string(tokenBytes)
	}

	return tokens
}

// controllerNamespace returns the namespace the controller is running in.
// Uses the POD_NAMESPACE downward API env var, falling back to "potoo-system".
func controllerNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "potoo-system"
}

// SetupWithManager registers the controller with the manager.
func (r *NotificationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NotificationPolicy{}).
		Complete(r)
}
