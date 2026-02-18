// Package requirements detects missing companion resources that a workload
// likely needs but doesn't have.
//
// # Contract
//
// The Evaluator runs a set of RequirementRules against each workload in the cluster.
// Unlike adapters (which parse existing constraints), rules reason about absence.
//
// # Built-in Rules (Phase 4)
//
//   - istio-routing: If workload has sidecar.istio.io/status annotation, check for
//     VirtualService or DestinationRule referencing it.
//
//   - prometheus-monitor: If workload has port named "metrics" or "http-metrics",
//     check for ServiceMonitor or PodMonitor matching its labels.
//
//   - istio-mtls: If namespace has istio-injection=enabled label, check for
//     PeerAuthentication in the namespace.
//
//   - cert-issuer: If workload references a cert-manager Certificate, check that
//     the referenced ClusterIssuer or Issuer exists.
//
//   - crd-installed: If workload triggers other rules, check that the CRDs
//     those rules depend on are actually installed in the cluster.
//
//   - annotation-requirements: If workload has a potoo.io/requires annotation,
//     parse the YAML entries and check that declared companion resources exist.
//
// # Debouncing
//
// All missing-resource notifications are debounced (configurable, default 120s).
// This prevents false positives when GitOps tools deploy resources in unpredictable order.
//
// # Constructor
//
//	func NewEvaluator(indexer *indexer.Indexer, evalCtx types.RequirementEvalContext, logger *zap.Logger) *Evaluator
//	func (e *Evaluator) RegisterRule(rule types.RequirementRule)
//	func (e *Evaluator) Evaluate(ctx context.Context, workload *unstructured.Unstructured) ([]types.Constraint, error)
package requirements
