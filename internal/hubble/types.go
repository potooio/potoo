package hubble

import (
	"time"
)

// FlowDrop represents a dropped network flow observed by Hubble.
type FlowDrop struct {
	// Time when the flow was observed
	Time time.Time

	// Source endpoint information
	Source Endpoint

	// Destination endpoint information
	Destination Endpoint

	// IP information
	IP IPInfo

	// L4 protocol information
	L4 L4Info

	// DropReason describes why the flow was dropped
	DropReason DropReason

	// PolicyName is the name of the policy that caused the drop (if known)
	PolicyName string

	// TraceID is the Hubble trace ID for correlation
	TraceID string
}

// Endpoint represents a source or destination in a flow.
type Endpoint struct {
	// Identity is the Cilium security identity
	Identity uint32

	// Namespace of the pod
	Namespace string

	// PodName is the name of the pod
	PodName string

	// Labels are the Kubernetes labels on the pod
	Labels map[string]string

	// Workloads contains the workload references (e.g., deployment, statefulset)
	Workloads []WorkloadRef
}

// WorkloadRef identifies a workload that owns a pod.
type WorkloadRef struct {
	Kind string
	Name string
}

// IPInfo contains IP-level information.
type IPInfo struct {
	Source      string
	Destination string
}

// L4Info contains L4 protocol information.
type L4Info struct {
	Protocol        Protocol
	SourcePort      uint32
	DestinationPort uint32

	// TCP-specific fields
	TCP *TCPInfo
}

// Protocol represents the L4 protocol.
type Protocol string

const (
	ProtocolTCP     Protocol = "TCP"
	ProtocolUDP     Protocol = "UDP"
	ProtocolICMP    Protocol = "ICMP"
	ProtocolUnknown Protocol = "UNKNOWN"
)

// TCPInfo contains TCP-specific information.
type TCPInfo struct {
	Flags TCPFlags
}

// TCPFlags represents TCP connection flags.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
}

// DropReason describes why a flow was dropped.
type DropReason string

const (
	// Policy-related drops
	DropReasonPolicy          DropReason = "POLICY_DENIED"
	DropReasonPolicyL3        DropReason = "POLICY_DENIED_L3"
	DropReasonPolicyL4        DropReason = "POLICY_DENIED_L4"
	DropReasonPolicyL7        DropReason = "POLICY_DENIED_L7"
	DropReasonPolicyAuth      DropReason = "POLICY_AUTH_REQUIRED"
	DropReasonNoNetworkPolicy DropReason = "NO_NETWORK_POLICY"
	DropReasonIngressDenied   DropReason = "INGRESS_DENIED"
	DropReasonEgressDenied    DropReason = "EGRESS_DENIED"

	// Non-policy drops
	DropReasonInvalidPacket   DropReason = "INVALID_PACKET"
	DropReasonTTLExceeded     DropReason = "TTL_EXCEEDED"
	DropReasonNoMapping       DropReason = "NO_MAPPING"
	DropReasonInvalidHeader   DropReason = "INVALID_HEADER"
	DropReasonProxyRedirect   DropReason = "PROXY_REDIRECT_FAILED"
	DropReasonHostUnreachable DropReason = "HOST_UNREACHABLE"

	// Unknown reason
	DropReasonUnknown DropReason = "UNKNOWN"
)

// String returns the string representation of the drop reason.
func (r DropReason) String() string {
	return string(r)
}

// IsPolicyDrop returns true if the drop was caused by a policy.
func (r DropReason) IsPolicyDrop() bool {
	switch r {
	case DropReasonPolicy, DropReasonPolicyL3, DropReasonPolicyL4, DropReasonPolicyL7,
		DropReasonPolicyAuth, DropReasonNoNetworkPolicy, DropReasonIngressDenied, DropReasonEgressDenied:
		return true
	default:
		return false
	}
}

// Verdict represents the flow verdict from Hubble.
type Verdict int32

const (
	VerdictUnknown    Verdict = 0
	VerdictForwarded  Verdict = 1
	VerdictDropped    Verdict = 2
	VerdictError      Verdict = 3
	VerdictAudit      Verdict = 4
	VerdictRedirected Verdict = 5
	VerdictTraced     Verdict = 6
	VerdictTranslated Verdict = 7
)

// ConnectionState tracks the client's connection to Hubble Relay.
type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateReconnecting ConnectionState = "reconnecting"
)
