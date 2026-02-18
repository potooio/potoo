// Package controller implements Kubernetes controllers for Potoo-owned CRDs.
//
// Unlike the other internal packages which use custom runnable loops via
// mgr.Add(), this package uses controller-runtime's Reconciler pattern because
// it watches Potoo's own typed CRDs (not external unstructured objects).
package controller

import (
	"context"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/discovery"
)

// ConstraintProfileReconciler reconciles ConstraintProfile resources.
// On create/update, it registers the profile's GVR with the discovery engine.
// On delete, it unregisters the profile and cleans up associated constraints.
type ConstraintProfileReconciler struct {
	Client client.Client
	Logger *zap.Logger
	Engine *discovery.Engine
}

func (r *ConstraintProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Logger.With(zap.String("profile", req.Name))

	var profile v1alpha1.ConstraintProfile
	if err := r.Client.Get(ctx, req.NamespacedName, &profile); err != nil {
		if apierrors.IsNotFound(err) {
			// Profile deleted — unregister from engine
			log.Info("ConstraintProfile deleted, unregistering")
			r.Engine.UnregisterProfile(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Register or update the profile in the engine
	log.Info("Reconciling ConstraintProfile",
		zap.String("adapter", profile.Spec.Adapter),
		zap.String("group", profile.Spec.GVR.Group),
		zap.String("resource", profile.Spec.GVR.Resource),
		zap.Bool("enabled", profile.Spec.Enabled),
	)

	if err := r.Engine.RegisterProfile(&profile); err != nil {
		log.Error("Failed to register profile", zap.Error(err))
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the manager.
func (r *ConstraintProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ConstraintProfile{}).
		Complete(r)
}
