// Package mcp implements a Model Context Protocol server that exposes
// Potoo's data to AI agents.
//
// # Overview
//
// The MCP server allows AI agents (Claude, Copilot, custom SRE bots) to
// query constraints, explain failures, pre-check deployments, and get
// structured remediation steps — all without parsing CRDs or kubectl output.
//
// # Transport
//
// Supports two transports:
//   - SSE (Server-Sent Events): for remote agents connecting over HTTP
//   - stdio: for local agents (e.g., Claude Code running on the same machine)
//
// # Privacy
//
// MCP responses respect the same NotificationPolicy scoping as all other outputs.
// The calling agent's identity (bearer token or K8s ServiceAccount) determines
// the detail level of the response.
//
// # Tools
//
// The MCP server exposes these tools:
//
//	potoo_query
//	  Query constraints affecting a namespace or workload.
//	  Params: namespace (required), workload_name, workload_labels, constraint_type, severity, include_remediation
//	  Returns: ConstraintQueryResult
//
//	potoo_explain
//	  Explain which constraint caused a specific error message.
//	  Params: error_message (required), namespace (required), workload_name
//	  Returns: ExplainResult
//
//	potoo_check
//	  Pre-check whether a manifest would be blocked.
//	  Params: manifest (YAML string, required)
//	  Returns: CheckResult
//
//	potoo_list_namespaces
//	  List all namespaces with constraint summaries.
//	  Returns: []NamespaceSummary
//
//	potoo_remediation
//	  Get detailed remediation for a specific constraint.
//	  Params: constraint_name (required), namespace (required)
//	  Returns: RemediationResult
//
// # Resources
//
//	potoo://reports/{namespace}      → full ConstraintReport as JSON
//	potoo://constraints/{ns}/{name}  → single constraint detail
//	potoo://health                   → operational health
//	potoo://capabilities             → what this instance can do
//
// # Constructor
//
//	func NewServer(indexer *indexer.Indexer, opts ServerOptions) *Server
//	func (s *Server) Start(ctx context.Context) error
//
//	type ServerOptions struct {
//	    Port            int       // default 8090
//	    Transport       string    // "sse" or "stdio"
//	    PrivacyResolver PrivacyResolverFunc
//	    Logger          *zap.Logger
//	}
package mcp
