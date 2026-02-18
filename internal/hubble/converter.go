package hubble

import (
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// FlowConverter converts Hubble proto flow messages to internal FlowDrop types.
// This provides the conversion layer between the Hubble proto types and our
// internal representation.
//
// NOTE: This file contains the conversion logic for when Cilium proto types are imported.
// The actual proto import requires: github.com/cilium/cilium/api/v1/flow
// For now, this provides a structured way to build FlowDrop from raw data.

// FlowDropBuilder helps construct FlowDrop events.
type FlowDropBuilder struct {
	drop FlowDrop
}

// NewFlowDropBuilder creates a new FlowDropBuilder.
func NewFlowDropBuilder() *FlowDropBuilder {
	return &FlowDropBuilder{
		drop: FlowDrop{
			Time: time.Now(),
		},
	}
}

// WithTime sets the flow time.
func (b *FlowDropBuilder) WithTime(t time.Time) *FlowDropBuilder {
	b.drop.Time = t
	return b
}

// WithTraceID sets the trace ID.
func (b *FlowDropBuilder) WithTraceID(traceID string) *FlowDropBuilder {
	b.drop.TraceID = traceID
	return b
}

// WithSource sets the source endpoint.
func (b *FlowDropBuilder) WithSource(namespace, podName string, labels map[string]string) *FlowDropBuilder {
	b.drop.Source = Endpoint{
		Namespace: namespace,
		PodName:   podName,
		Labels:    labels,
	}
	return b
}

// WithSourceIdentity sets the source security identity.
func (b *FlowDropBuilder) WithSourceIdentity(identity uint32) *FlowDropBuilder {
	b.drop.Source.Identity = identity
	return b
}

// WithSourceWorkload adds a workload reference to the source.
func (b *FlowDropBuilder) WithSourceWorkload(kind, name string) *FlowDropBuilder {
	b.drop.Source.Workloads = append(b.drop.Source.Workloads, WorkloadRef{
		Kind: kind,
		Name: name,
	})
	return b
}

// WithDestination sets the destination endpoint.
func (b *FlowDropBuilder) WithDestination(namespace, podName string, labels map[string]string) *FlowDropBuilder {
	b.drop.Destination = Endpoint{
		Namespace: namespace,
		PodName:   podName,
		Labels:    labels,
	}
	return b
}

// WithDestinationIdentity sets the destination security identity.
func (b *FlowDropBuilder) WithDestinationIdentity(identity uint32) *FlowDropBuilder {
	b.drop.Destination.Identity = identity
	return b
}

// WithDestinationWorkload adds a workload reference to the destination.
func (b *FlowDropBuilder) WithDestinationWorkload(kind, name string) *FlowDropBuilder {
	b.drop.Destination.Workloads = append(b.drop.Destination.Workloads, WorkloadRef{
		Kind: kind,
		Name: name,
	})
	return b
}

// WithIP sets the IP addresses.
func (b *FlowDropBuilder) WithIP(source, destination string) *FlowDropBuilder {
	b.drop.IP = IPInfo{
		Source:      source,
		Destination: destination,
	}
	return b
}

// WithTCP sets TCP L4 information.
func (b *FlowDropBuilder) WithTCP(srcPort, dstPort uint32, flags TCPFlags) *FlowDropBuilder {
	b.drop.L4 = L4Info{
		Protocol:        ProtocolTCP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		TCP: &TCPInfo{
			Flags: flags,
		},
	}
	return b
}

// WithUDP sets UDP L4 information.
func (b *FlowDropBuilder) WithUDP(srcPort, dstPort uint32) *FlowDropBuilder {
	b.drop.L4 = L4Info{
		Protocol:        ProtocolUDP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
	}
	return b
}

// WithDropReason sets the drop reason.
func (b *FlowDropBuilder) WithDropReason(reason DropReason) *FlowDropBuilder {
	b.drop.DropReason = reason
	return b
}

// WithPolicyName sets the policy name that caused the drop.
func (b *FlowDropBuilder) WithPolicyName(name string) *FlowDropBuilder {
	b.drop.PolicyName = name
	return b
}

// Build returns the constructed FlowDrop.
// The returned value does not share map or slice references with the builder.
func (b *FlowDropBuilder) Build() FlowDrop {
	result := b.drop
	result.Source.Labels = copyStringMap(b.drop.Source.Labels)
	result.Destination.Labels = copyStringMap(b.drop.Destination.Labels)
	result.Source.Workloads = copyWorkloads(b.drop.Source.Workloads)
	result.Destination.Workloads = copyWorkloads(b.drop.Destination.Workloads)
	return result
}

func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyWorkloads(ws []WorkloadRef) []WorkloadRef {
	if ws == nil {
		return nil
	}
	result := make([]WorkloadRef, len(ws))
	copy(result, ws)
	return result
}

// ParseDropReason converts a Hubble drop reason code to our internal type.
func ParseDropReason(code int32) DropReason {
	switch flowpb.DropReason(code) {
	case flowpb.DropReason_POLICY_DENIED, flowpb.DropReason_POLICY_DENY:
		return DropReasonPolicy
	case flowpb.DropReason_AUTH_REQUIRED, flowpb.DropReason_INVALID_IDENTITY:
		return DropReasonPolicyAuth
	case flowpb.DropReason_CT_NO_MAP_FOUND, flowpb.DropReason_FIB_LOOKUP_FAILED:
		return DropReasonNoMapping
	case flowpb.DropReason_INVALID_SOURCE_IP, flowpb.DropReason_INVALID_PACKET_DROPPED:
		return DropReasonInvalidPacket
	case flowpb.DropReason_TTL_EXCEEDED:
		return DropReasonTTLExceeded
	case flowpb.DropReason_PROXY_REDIRECTION_NOT_SUPPORTED_FOR_PROTOCOL:
		return DropReasonProxyRedirect
	default:
		return DropReasonUnknown
	}
}

// parseLabels converts Cilium proto labels ([]string in "source:key=value" format)
// to a map[string]string, stripping the source prefix.
func parseLabels(protoLabels []string) map[string]string {
	if len(protoLabels) == 0 {
		return nil
	}
	result := make(map[string]string, len(protoLabels))
	for _, l := range protoLabels {
		// Strip source prefix (e.g., "k8s:" from "k8s:app=frontend")
		if idx := strings.Index(l, ":"); idx >= 0 {
			l = l[idx+1:]
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		} else if parts[0] != "" {
			result[parts[0]] = ""
		}
	}
	return result
}

// ParseProtocol converts an IP protocol number to our Protocol type.
func ParseProtocol(proto uint8) Protocol {
	switch proto {
	case 6:
		return ProtocolTCP
	case 17:
		return ProtocolUDP
	case 1:
		return ProtocolICMP
	default:
		return ProtocolUnknown
	}
}
