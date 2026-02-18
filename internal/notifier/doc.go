// Package notifier renders constraint notifications at the appropriate privacy level
// and dispatches them via configured channels (K8s Events, ConstraintReport CRD, webhooks).
//
// # Contract
//
// The Dispatcher:
//  1. Receives CorrelatedNotification from the correlator (or direct Constraint from indexer)
//  2. Determines the detail level from the active NotificationPolicy
//  3. Renders the notification message at that detail level:
//     - summary:  constraint type + generic effect + remediation contact (no cross-NS details)
//     - detailed: + specific ports + constraint name (same namespace only)
//     - full:     + cross-namespace details + policy source + Hubble flow data
//  4. Dispatches via enabled channels:
//     - K8s Event on the affected workload (always enabled)
//     - ConstraintReport CRD update for the namespace
//     - Slack/webhook (if configured, for Critical+ severity)
//
// # Deduplication
//
// Track (constraintUID, workloadUID) pairs. Suppress re-notification within
// configurable window (default 60 minutes). Reset on constraint change (new UID or spec change).
//
// # Rate Limiting
//
// Circuit breaker: max 100 events/minute per namespace. Excess notifications are
// dropped with a metric increment.
//
// # Types
//
//	type Dispatcher struct { ... }
//	func NewDispatcher(client kubernetes.Interface, logger *zap.Logger, opts DispatcherOptions, policyRouter *PolicyRouter) *Dispatcher
//	func (d *Dispatcher) Dispatch(ctx context.Context, n correlator.CorrelatedNotification) error
//	func (d *Dispatcher) RenderMessage(c types.Constraint, level types.DetailLevel) string
//
//	type DispatcherOptions struct {
//	    SuppressDuplicateMinutes int    // default 60
//	    RateLimitPerMinute       int    // default 100
//	    RemediationContact       string // shown in summary-level messages
//	}
//
// # Rendering Rules (see docs/PRIVACY_MODEL.md for full details)
//
// summary level:
//
//	"⚠️ {ConstraintType} constraint is affecting your workload `{workloadName}`.
//	 {GenericEffect}. Contact {contact} for assistance."
//
// detailed level:
//
//	"⚠️ {ConstraintType} `{constraintName}` is affecting `{workloadName}`.
//	 {SpecificEffect with ports}. {RemediationHint}"
//
// full level:
//
//	"⚠️ {Source GVR} `{namespace/constraintName}` is blocking {workloadKind}
//	 `{workloadNamespace/workloadName}`. {FullDetails}. Policy created {timestamp}."
package notifier
