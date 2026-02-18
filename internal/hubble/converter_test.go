package hubble

import (
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/stretchr/testify/assert"
)

func TestFlowDropBuilder(t *testing.T) {
	now := time.Now()
	drop := NewFlowDropBuilder().
		WithTime(now).
		WithTraceID("trace-123").
		WithSource("production", "frontend-abc", map[string]string{"app": "frontend"}).
		WithSourceIdentity(12345).
		WithSourceWorkload("Deployment", "frontend").
		WithDestination("production", "backend-xyz", map[string]string{"app": "backend"}).
		WithDestinationIdentity(67890).
		WithDestinationWorkload("Deployment", "backend").
		WithIP("10.0.1.5", "10.0.2.10").
		WithTCP(45678, 8080, TCPFlags{SYN: true}).
		WithDropReason(DropReasonPolicy).
		WithPolicyName("deny-external").
		Build()

	assert.Equal(t, now, drop.Time)
	assert.Equal(t, "trace-123", drop.TraceID)

	// Source
	assert.Equal(t, "production", drop.Source.Namespace)
	assert.Equal(t, "frontend-abc", drop.Source.PodName)
	assert.Equal(t, uint32(12345), drop.Source.Identity)
	assert.Equal(t, "frontend", drop.Source.Labels["app"])
	assert.Len(t, drop.Source.Workloads, 1)
	assert.Equal(t, "Deployment", drop.Source.Workloads[0].Kind)
	assert.Equal(t, "frontend", drop.Source.Workloads[0].Name)

	// Destination
	assert.Equal(t, "production", drop.Destination.Namespace)
	assert.Equal(t, "backend-xyz", drop.Destination.PodName)
	assert.Equal(t, uint32(67890), drop.Destination.Identity)
	assert.Equal(t, "backend", drop.Destination.Labels["app"])
	assert.Len(t, drop.Destination.Workloads, 1)
	assert.Equal(t, "Deployment", drop.Destination.Workloads[0].Kind)
	assert.Equal(t, "backend", drop.Destination.Workloads[0].Name)

	// IP
	assert.Equal(t, "10.0.1.5", drop.IP.Source)
	assert.Equal(t, "10.0.2.10", drop.IP.Destination)

	// L4
	assert.Equal(t, ProtocolTCP, drop.L4.Protocol)
	assert.Equal(t, uint32(45678), drop.L4.SourcePort)
	assert.Equal(t, uint32(8080), drop.L4.DestinationPort)
	assert.NotNil(t, drop.L4.TCP)
	assert.True(t, drop.L4.TCP.Flags.SYN)
	assert.False(t, drop.L4.TCP.Flags.ACK)

	// Drop info
	assert.Equal(t, DropReasonPolicy, drop.DropReason)
	assert.Equal(t, "deny-external", drop.PolicyName)
}

func TestFlowDropBuilder_UDP(t *testing.T) {
	drop := NewFlowDropBuilder().
		WithSource("ns", "pod1", nil).
		WithDestination("ns", "pod2", nil).
		WithUDP(12345, 53).
		Build()

	assert.Equal(t, ProtocolUDP, drop.L4.Protocol)
	assert.Equal(t, uint32(12345), drop.L4.SourcePort)
	assert.Equal(t, uint32(53), drop.L4.DestinationPort)
	assert.Nil(t, drop.L4.TCP)
}

func TestFlowDropBuilder_Build_DoesNotShareReferences(t *testing.T) {
	b := NewFlowDropBuilder().
		WithSource("ns", "pod1", map[string]string{"app": "web"}).
		WithSourceWorkload("Deployment", "web").
		WithDestination("ns", "pod2", map[string]string{"app": "api"}).
		WithDestinationWorkload("Deployment", "api")

	drop := b.Build()

	// Mutate the builder's internal state after Build()
	b.WithSource("ns", "pod1-mutated", map[string]string{"app": "mutated"})
	b.WithSourceWorkload("StatefulSet", "mutated")
	b.WithDestination("ns", "pod2-mutated", map[string]string{"app": "mutated"})
	b.WithDestinationWorkload("StatefulSet", "mutated")

	// The previously built drop must be unaffected
	assert.Equal(t, "web", drop.Source.Labels["app"])
	assert.Equal(t, "api", drop.Destination.Labels["app"])
	assert.Len(t, drop.Source.Workloads, 1)
	assert.Equal(t, "Deployment", drop.Source.Workloads[0].Kind)
	assert.Len(t, drop.Destination.Workloads, 1)
	assert.Equal(t, "Deployment", drop.Destination.Workloads[0].Kind)
}

func TestParseDropReason(t *testing.T) {
	tests := []struct {
		name     string
		code     int32
		expected DropReason
	}{
		{"POLICY_DENIED", int32(flowpb.DropReason_POLICY_DENIED), DropReasonPolicy},
		{"POLICY_DENY", int32(flowpb.DropReason_POLICY_DENY), DropReasonPolicy},
		{"AUTH_REQUIRED", int32(flowpb.DropReason_AUTH_REQUIRED), DropReasonPolicyAuth},
		{"INVALID_IDENTITY", int32(flowpb.DropReason_INVALID_IDENTITY), DropReasonPolicyAuth},
		{"CT_NO_MAP_FOUND", int32(flowpb.DropReason_CT_NO_MAP_FOUND), DropReasonNoMapping},
		{"FIB_LOOKUP_FAILED", int32(flowpb.DropReason_FIB_LOOKUP_FAILED), DropReasonNoMapping},
		{"INVALID_SOURCE_IP", int32(flowpb.DropReason_INVALID_SOURCE_IP), DropReasonInvalidPacket},
		{"INVALID_PACKET_DROPPED", int32(flowpb.DropReason_INVALID_PACKET_DROPPED), DropReasonInvalidPacket},
		{"TTL_EXCEEDED", int32(flowpb.DropReason_TTL_EXCEEDED), DropReasonTTLExceeded},
		{"PROXY_REDIRECTION_NOT_SUPPORTED", int32(flowpb.DropReason_PROXY_REDIRECTION_NOT_SUPPORTED_FOR_PROTOCOL), DropReasonProxyRedirect},
		{"unknown code", 999, DropReasonUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseDropReason(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected Protocol
	}{
		{6, ProtocolTCP},
		{17, ProtocolUDP},
		{1, ProtocolICMP},
		{255, ProtocolUnknown},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := ParseProtocol(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDropReason_IsPolicyDrop(t *testing.T) {
	policyDrops := []DropReason{
		DropReasonPolicy,
		DropReasonPolicyL3,
		DropReasonPolicyL4,
		DropReasonPolicyL7,
		DropReasonPolicyAuth,
		DropReasonNoNetworkPolicy,
		DropReasonIngressDenied,
		DropReasonEgressDenied,
	}

	for _, r := range policyDrops {
		assert.True(t, r.IsPolicyDrop(), "expected %s to be a policy drop", r)
	}

	nonPolicyDrops := []DropReason{
		DropReasonInvalidPacket,
		DropReasonTTLExceeded,
		DropReasonNoMapping,
		DropReasonUnknown,
	}

	for _, r := range nonPolicyDrops {
		assert.False(t, r.IsPolicyDrop(), "expected %s to NOT be a policy drop", r)
	}
}

func TestParseLabels(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected map[string]string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:  "standard k8s labels",
			input: []string{"k8s:app=frontend", "k8s:version=v2"},
			expected: map[string]string{
				"app":     "frontend",
				"version": "v2",
			},
		},
		{
			name:  "reserved identity",
			input: []string{"reserved:host"},
			expected: map[string]string{
				"host": "",
			},
		},
		{
			name:  "label with equals in value",
			input: []string{"k8s:config=key=value"},
			expected: map[string]string{
				"config": "key=value",
			},
		},
		{
			name:  "no source prefix",
			input: []string{"app=backend"},
			expected: map[string]string{
				"app": "backend",
			},
		},
		{
			name:  "mixed formats",
			input: []string{"k8s:app=web", "reserved:world", "custom:tier=frontend"},
			expected: map[string]string{
				"app":   "web",
				"world": "",
				"tier":  "frontend",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLabels(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
