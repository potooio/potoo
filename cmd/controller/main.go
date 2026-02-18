package main

import (
	"context"
	"flag"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/adapters"
	"github.com/potooio/potoo/internal/adapters/cilium"
	"github.com/potooio/potoo/internal/adapters/gatekeeper"
	istioAdapter "github.com/potooio/potoo/internal/adapters/istio"
	"github.com/potooio/potoo/internal/adapters/kyverno"
	"github.com/potooio/potoo/internal/adapters/limitrange"
	"github.com/potooio/potoo/internal/adapters/networkpolicy"
	"github.com/potooio/potoo/internal/adapters/resourcequota"
	"github.com/potooio/potoo/internal/adapters/webhookconfig"
	internalapi "github.com/potooio/potoo/internal/api"
	internalcontroller "github.com/potooio/potoo/internal/controller"
	"github.com/potooio/potoo/internal/correlator"
	discoveryengine "github.com/potooio/potoo/internal/discovery"
	"github.com/potooio/potoo/internal/hubble"
	"github.com/potooio/potoo/internal/indexer"
	"github.com/potooio/potoo/internal/mcp"
	"github.com/potooio/potoo/internal/notifier"
	"github.com/potooio/potoo/internal/requirements"
	"github.com/potooio/potoo/internal/types"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr            string
		healthAddr             string
		leaderElect            bool
		rescanInterval         time.Duration
		annotatorDebounce      time.Duration
		annotatorCacheTTL      time.Duration
		reportDebounce         time.Duration
		reportWorkers          int
		requirementDebounce    time.Duration
		hubbleAddr             string
		hubbleEnabled          bool
		additionalPolicyGroups string
		additionalNameHints    string
		checkCRDAnnotations    bool
		webhookURL             string
		webhookTimeout         int
		webhookInsecureSkip    bool
		webhookMinSeverity     string
		webhookAuthToken       string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&healthAddr, "health-probe-bind-address", ":8081", "The address the health probe endpoint binds to.")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Enable leader election for controller manager.")
	flag.DurationVar(&rescanInterval, "rescan-interval", 5*time.Minute, "How often to rescan for new CRDs.")
	flag.DurationVar(&annotatorDebounce, "annotator-debounce", 30*time.Second, "Minimum time between annotation PATCHes for the same workload.")
	flag.DurationVar(&annotatorCacheTTL, "annotator-cache-ttl", 30*time.Second, "How long namespace workload lists are cached before re-fetching.")
	flag.DurationVar(&reportDebounce, "report-debounce", 10*time.Second, "Minimum time between ConstraintReport reconciles for the same namespace.")
	flag.IntVar(&reportWorkers, "report-workers", 3, "Number of concurrent workers processing ConstraintReport reconciles.")
	flag.DurationVar(&requirementDebounce, "requirement-debounce", 120*time.Second, "How long to wait before alerting on missing companion resources.")
	flag.StringVar(&hubbleAddr, "hubble-relay-address", "hubble-relay.kube-system.svc:4245", "Hubble Relay gRPC address.")
	flag.BoolVar(&hubbleEnabled, "hubble-enabled", false, "Enable Hubble flow observation for real-time traffic drop detection.")
	flag.StringVar(&additionalPolicyGroups, "additional-policy-groups", "", "Comma-separated list of additional API groups to treat as policy sources.")
	flag.StringVar(&additionalNameHints, "additional-name-hints", "", "Comma-separated list of additional resource name substrings for heuristic detection.")
	flag.BoolVar(&checkCRDAnnotations, "check-crd-annotations", true, "Check CRDs for potoo.io/is-policy annotation during discovery scan.")
	flag.StringVar(&webhookURL, "webhook-url", "", "URL for generic webhook notifications (HTTP POST).")
	flag.IntVar(&webhookTimeout, "webhook-timeout", 10, "Webhook HTTP request timeout in seconds.")
	flag.BoolVar(&webhookInsecureSkip, "webhook-insecure-skip-verify", false, "Disable TLS certificate verification for webhook (insecure).")
	flag.StringVar(&webhookMinSeverity, "webhook-min-severity", "Warning", "Minimum severity for webhook notifications (Critical, Warning, Info).")
	flag.StringVar(&webhookAuthToken, "webhook-auth-token", "", "Bearer token for webhook Authorization header. Overridden by POTOO_WEBHOOK_AUTH_TOKEN env var if set.")
	flag.Parse()

	// Environment variable override for webhook auth token (allows Secret mounting).
	if envToken := os.Getenv("POTOO_WEBHOOK_AUTH_TOKEN"); envToken != "" {
		webhookAuthToken = envToken
	}

	// Setup logger
	logConfig := zap.NewProductionConfig()
	logConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, err := logConfig.Build()
	if err != nil {
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Potoo",
		zap.String("version", "dev"),
		zap.Bool("leader_elect", leaderElect),
		zap.Duration("rescan_interval", rescanInterval),
		zap.Bool("hubble_enabled", hubbleEnabled),
	)

	// Build constraint indexer with annotator + report reconciler callbacks.
	// Created before the manager so its API handlers can be registered on the
	// metrics server via ExtraHandlers.
	var annotatorRef atomic.Pointer[notifier.WorkloadAnnotator]
	var reportReconcilerRef atomic.Pointer[notifier.ReportReconciler]
	idx := indexer.New(func(event indexer.IndexEvent) {
		logger.Debug("Index event",
			zap.String("type", event.Type),
			zap.String("constraint", event.Constraint.Name),
		)
		if a := annotatorRef.Load(); a != nil {
			a.OnIndexChange(event)
		}
		if rr := reportReconcilerRef.Load(); rr != nil {
			rr.OnIndexChange(event)
		}
	})

	// Build adapter registry
	registry := adapters.NewRegistry()
	mustRegister(logger, registry, networkpolicy.New())
	mustRegister(logger, registry, resourcequota.New())
	mustRegister(logger, registry, limitrange.New())
	mustRegister(logger, registry, webhookconfig.New())
	mustRegister(logger, registry, gatekeeper.New())
	mustRegister(logger, registry, kyverno.New())
	mustRegister(logger, registry, cilium.New())
	mustRegister(logger, registry, istioAdapter.New())

	logger.Info("Adapter registry initialized",
		zap.Int("adapter_count", len(registry.All())),
		zap.Int("handled_gvrs", len(registry.HandledGVRs())),
	)

	// Setup controller-runtime manager with API handlers on the metrics server.
	// The webhook queries the controller at this address for constraint data.
	cfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "potoo-leader",
		HealthProbeBindAddress: healthAddr,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			ExtraHandlers: internalapi.ExtraHandlers(idx, logger, internalapi.CapabilitiesHandlerOptions{Adapters: internalapi.DefaultAdapters()}),
		},
	})
	if err != nil {
		logger.Fatal("Unable to create manager", zap.Error(err))
	}

	// Register health checks
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Fatal("Unable to set up health check", zap.Error(err))
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Fatal("Unable to set up readiness check", zap.Error(err))
	}

	// Build clients
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		logger.Fatal("Failed to create discovery client", zap.Error(err))
	}

	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Fatal("Failed to create dynamic client", zap.Error(err))
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Fatal("Failed to create clientset", zap.Error(err))
	}

	// Build discovery engine
	engine := discoveryengine.NewEngine(
		logger,
		discoveryClient,
		dynamicClient,
		registry,
		idx,
		rescanInterval,
	)

	// Configure discovery heuristics
	if additionalPolicyGroups != "" {
		engine.SetAdditionalGroups(splitCSV(additionalPolicyGroups))
	}
	if additionalNameHints != "" {
		engine.SetAdditionalHints(splitCSV(additionalNameHints))
	}
	engine.SetCheckAnnotation(checkCRDAnnotations)

	// Setup ConstraintProfile reconciler (controller-runtime reconciler because
	// it watches a Potoo-owned typed CRD, not external unstructured objects).
	profileReconciler := &internalcontroller.ConstraintProfileReconciler{
		Client: mgr.GetClient(),
		Logger: logger,
		Engine: engine,
	}
	if err := profileReconciler.SetupWithManager(mgr); err != nil {
		logger.Fatal("Failed to set up ConstraintProfile controller", zap.Error(err))
	}

	// Setup signal handler context (before Hubble client so it responds to SIGTERM)
	ctx := ctrl.SetupSignalHandler()

	// Build Hubble client (optional)
	var hubbleClient *hubble.Client
	if hubbleEnabled {
		var clientErr error
		hubbleClient, clientErr = hubble.NewClient(ctx, hubble.ClientOptions{
			RelayAddress: hubbleAddr,
			Logger:       logger,
		})
		if clientErr != nil {
			logger.Fatal("Failed to create Hubble client", zap.Error(clientErr))
		}
		logger.Info("Hubble client created", zap.String("relay_address", hubbleAddr))
	}

	// Build correlator
	corr := correlator.NewWithOptions(idx, clientset, logger, correlator.CorrelatorOptions{
		HubbleClient: hubbleClient,
	})

	// Build PolicyRouter for NotificationPolicy CRD-driven notification routing.
	policyRouter := notifier.NewPolicyRouter(logger)

	// Build notification dispatcher
	dispatcherOpts := notifier.DefaultDispatcherOptions()

	// Configure static webhook sender from CLI flags (fallback when no NotificationPolicy CRDs exist).
	var webhookSender *notifier.WebhookSender
	if webhookURL != "" {
		webhookCfg := notifier.WebhookSenderConfig{
			URL:                webhookURL,
			TimeoutSeconds:     webhookTimeout,
			InsecureSkipVerify: webhookInsecureSkip,
			MinSeverity:        webhookMinSeverity,
			AuthToken:          webhookAuthToken,
		}
		var wsErr error
		webhookSender, wsErr = notifier.NewWebhookSender(logger, webhookCfg)
		if wsErr != nil {
			logger.Fatal("Failed to create webhook sender", zap.Error(wsErr))
		}
		dispatcherOpts.Senders = append(dispatcherOpts.Senders, webhookSender)
		logger.Info("Webhook sender configured (static, from CLI flags)", zap.String("url", notifier.RedactURL(webhookURL)))
	}

	dispatcher := notifier.NewDispatcher(clientset, logger, dispatcherOpts, policyRouter)

	// Build workload annotator
	annotatorOpts := notifier.DefaultWorkloadAnnotatorOptions()
	annotatorOpts.DebounceDuration = annotatorDebounce
	annotatorOpts.CacheTTL = annotatorCacheTTL
	annotator := notifier.NewWorkloadAnnotator(dynamicClient, idx, logger, annotatorOpts)
	annotatorRef.Store(annotator)

	// Build requirements evaluator context
	evalCtx := requirements.NewDynamicEvalContext(dynamicClient)

	// MCP evaluator: debounce=0 for immediate pre-check responses.
	mcpEvaluator := requirements.NewEvaluator(idx, evalCtx, logger)
	mcpEvaluator.SetDebounceDuration(0)
	registerRequirementRules(mcpEvaluator)

	// Report reconciler evaluator: configurable debounce (default 120s).
	reconcilerEvaluator := requirements.NewEvaluator(idx, evalCtx, logger)
	reconcilerEvaluator.SetDebounceDuration(requirementDebounce)
	registerRequirementRules(reconcilerEvaluator)

	// Build MCP server
	mcpOpts := mcp.DefaultServerOptions()
	mcpOpts.Logger = logger
	mcpOpts.Evaluator = mcpEvaluator
	mcpServer := mcp.NewServer(idx, mcpOpts)

	// Build report reconciler
	reconcilerOpts := notifier.DefaultReportReconcilerOptions()
	reconcilerOpts.DebounceDuration = reportDebounce
	reconcilerOpts.Workers = reportWorkers
	reportReconciler := notifier.NewReportReconciler(
		mgr.GetClient(), idx, logger, reconcilerOpts,
		reconcilerEvaluator, dynamicClient, policyRouter,
	)
	reportReconcilerRef.Store(reportReconciler)

	// Setup NotificationPolicy reconciler — watches NotificationPolicy CRDs and
	// updates the PolicyRouter so dispatcher/report reconciler route to the right channels.
	npReconciler := &internalcontroller.NotificationPolicyReconciler{
		Client:       mgr.GetClient(),
		Logger:       logger,
		PolicyRouter: policyRouter,
	}
	if err := npReconciler.SetupWithManager(mgr); err != nil {
		logger.Fatal("Failed to set up NotificationPolicy controller", zap.Error(err))
	}

	// Add runnable to initialize PolicyRouter context and handle cleanup.
	// The manager's context is available inside runnables and propagates cancellation.
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		policyRouter.SetContext(ctx)
		<-ctx.Done()
		policyRouter.Close()
		return nil
	}}); err != nil {
		logger.Fatal("Failed to add policy router lifecycle to manager", zap.Error(err))
	}

	// Add runnable to start discovery engine
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		return engine.Start(ctx)
	}}); err != nil {
		logger.Fatal("Failed to add discovery engine to manager", zap.Error(err))
	}

	// Add runnable to start correlator
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		return corr.Start(ctx)
	}}); err != nil {
		logger.Fatal("Failed to add correlator to manager", zap.Error(err))
	}

	// Add runnable to start workload annotator
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		return annotator.Start(ctx)
	}}); err != nil {
		logger.Fatal("Failed to add workload annotator to manager", zap.Error(err))
	}

	// Add runnable to start dispatcher loop
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		dispatcher.Start(ctx)
		// Process notifications from correlator
		for {
			select {
			case <-ctx.Done():
				return nil
			case notification, ok := <-corr.Notifications():
				if !ok {
					return nil
				}
				if err := dispatcher.Dispatch(ctx, notification); err != nil {
					logger.Error("Failed to dispatch notification", zap.Error(err))
				}
			}
		}
	}}); err != nil {
		logger.Fatal("Failed to add dispatcher to manager", zap.Error(err))
	}

	// Add runnable to log flow drop notifications (consumer for Hubble correlation)
	if hubbleEnabled {
		if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case notification, ok := <-corr.FlowDropNotifications():
					if !ok {
						return nil
					}
					logger.Info("Flow drop correlated",
						zap.String("source_pod", notification.SourcePodName),
						zap.String("dest_pod", notification.DestPodName),
						zap.String("constraint", notification.Constraint.Name),
						zap.Uint32("dest_port", notification.DestPort),
						zap.String("protocol", notification.Protocol),
					)
				}
			}
		}}); err != nil {
			logger.Fatal("Failed to add flow drop consumer to manager", zap.Error(err))
		}
	}

	// Add runnable to start MCP server
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		return mcpServer.Start(ctx)
	}}); err != nil {
		logger.Fatal("Failed to add MCP server to manager", zap.Error(err))
	}

	// Add runnable to start report reconciler
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		return reportReconciler.Start(ctx)
	}}); err != nil {
		logger.Fatal("Failed to add report reconciler to manager", zap.Error(err))
	}

	// Add runnable for evaluator cleanup
	if err := mgr.Add(&runnableFunc{fn: func(ctx context.Context) error {
		reconcilerEvaluator.StartCleanup(ctx)
		return nil
	}}); err != nil {
		logger.Fatal("Failed to add evaluator cleanup to manager", zap.Error(err))
	}

	// Start manager (blocks until context is cancelled)
	logger.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		logger.Fatal("Manager exited with error", zap.Error(err))
	}

	// Wait for webhook sender to drain queued notifications.
	if webhookSender != nil {
		webhookSender.Close()
	}

	// Cleanup
	if hubbleClient != nil {
		if err := hubbleClient.Close(); err != nil {
			logger.Error("Failed to close Hubble client", zap.Error(err))
		}
	}
	engine.Stop()
}

// registerRequirementRules registers all built-in requirement rules on the evaluator.
func registerRequirementRules(eval *requirements.Evaluator) {
	eval.RegisterRule(requirements.NewPrometheusMonitorRule())
	eval.RegisterRule(requirements.NewIstioRoutingRule())
	eval.RegisterRule(requirements.NewIstioMTLSRule())
	eval.RegisterRule(requirements.NewCertIssuerRule())
	eval.RegisterRule(requirements.NewCRDInstalledRule())
	eval.RegisterRule(requirements.NewAnnotationRule())
}

// mustRegister registers an adapter or exits on failure.
func mustRegister(logger *zap.Logger, registry *adapters.Registry, adapter types.Adapter) {
	if err := registry.Register(adapter); err != nil {
		logger.Fatal("Failed to register adapter",
			zap.String("adapter", adapter.Name()),
			zap.Error(err),
		)
	}
}

// runnableFunc is a helper to convert a function to a controller-runtime Runnable.
type runnableFunc struct {
	fn func(context.Context) error
}

func (r *runnableFunc) Start(ctx context.Context) error {
	return r.fn(ctx)
}

// splitCSV splits a comma-separated string into trimmed, non-empty items.
func splitCSV(s string) []string {
	var result []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}
