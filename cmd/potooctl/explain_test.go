package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchError(t *testing.T) {
	// Shared constraint fixtures
	allConstraints := []ConstraintInfo{
		{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
		{Name: "allow-ingress", Type: "NetworkIngress", Severity: "Warning"},
		{Name: "require-labels", Type: "Admission", Severity: "Critical"},
		{Name: "cpu-quota", Type: "ResourceLimit", Severity: "Warning"},
		{Name: "misc-policy", Type: "SecurityContext", Severity: "Info"},
	}

	tests := []struct {
		name               string
		errorMessage       string
		constraints        []ConstraintInfo
		wantMatchNames     []string
		wantConfidence     string
		wantExplanationSub string // substring of explanation
	}{
		// ----- Network patterns -----
		{
			name:               "connection_refused",
			errorMessage:       "dial tcp 10.0.0.1:443: connection refused",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network-related",
		},
		{
			name:               "connection_timed_out",
			errorMessage:       "Get https://api.example.com: connection timed out",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "network_unreachable",
			errorMessage:       "network unreachable",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "no_route_to_host",
			errorMessage:       "no route to host 10.0.0.5",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "dial_tcp",
			errorMessage:       "dial tcp 10.0.0.1:80: i/o timeout",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "io_timeout",
			errorMessage:       "i/o timeout when connecting to svc",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "egress_keyword",
			errorMessage:       "egress traffic blocked for pod",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "ingress_keyword",
			errorMessage:       "ingress not allowed",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		{
			name:               "case_insensitive_network",
			errorMessage:       "CONNECTION REFUSED by firewall",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
		// ----- Admission patterns -----
		{
			name:               "denied",
			errorMessage:       "admission webhook denied the request",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission controller",
		},
		{
			name:               "rejected",
			errorMessage:       "request rejected by policy",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		{
			name:               "forbidden",
			errorMessage:       "forbidden: user cannot create deployments",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		{
			name:               "webhook",
			errorMessage:       "webhook error in policy check",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		{
			name:               "not_allowed",
			errorMessage:       "operation not allowed by security policy",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		{
			name:               "policy_violation",
			errorMessage:       "policy violation detected in manifest",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		{
			name:               "constraint_keyword",
			errorMessage:       "constraint check failed",
			constraints:        allConstraints,
			wantMatchNames:     []string{"require-labels"},
			wantConfidence:     "high",
			wantExplanationSub: "admission",
		},
		// ----- Quota patterns -----
		{
			name:               "exceeded_quota",
			errorMessage:       "exceeded quota: requests.cpu",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota-related",
		},
		{
			name:               "resource_quota",
			errorMessage:       "resource quota limit reached",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		{
			name:               "limit_exceeded",
			errorMessage:       "memory limit exceeded for container",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		{
			name:               "insufficient",
			errorMessage:       "insufficient cpu resources available",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		{
			name:               "cpu_keyword",
			errorMessage:       "cpu usage too high",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		{
			name:               "memory_keyword",
			errorMessage:       "memory pressure detected",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		{
			name:               "storage_keyword",
			errorMessage:       "storage provisioning failed",
			constraints:        allConstraints,
			wantMatchNames:     []string{"cpu-quota"},
			wantConfidence:     "high",
			wantExplanationSub: "quota",
		},
		// ----- No match, returns all -----
		{
			name:               "unmatched_error_returns_all",
			errorMessage:       "something completely unrelated happened",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress", "require-labels", "cpu-quota", "misc-policy"},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		// ----- Edge cases -----
		{
			name:               "empty_error_returns_all",
			errorMessage:       "",
			constraints:        allConstraints,
			wantMatchNames:     []string{"deny-egress", "allow-ingress", "require-labels", "cpu-quota", "misc-policy"},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:               "empty_constraints_returns_empty",
			errorMessage:       "connection refused",
			constraints:        []ConstraintInfo{},
			wantMatchNames:     []string{},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:               "nil_constraints_returns_nil",
			errorMessage:       "connection refused",
			constraints:        nil,
			wantMatchNames:     nil,
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:               "network_error_no_network_constraints",
			errorMessage:       "connection refused",
			constraints:        []ConstraintInfo{{Name: "admission-only", Type: "Admission", Severity: "Critical"}},
			wantMatchNames:     []string{"admission-only"},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:               "admission_error_no_admission_constraints",
			errorMessage:       "denied by policy",
			constraints:        []ConstraintInfo{{Name: "net-only", Type: "NetworkEgress", Severity: "Critical"}},
			wantMatchNames:     []string{"net-only"},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:               "quota_error_no_quota_constraints",
			errorMessage:       "exceeded quota",
			constraints:        []ConstraintInfo{{Name: "net-only", Type: "NetworkEgress", Severity: "Critical"}},
			wantMatchNames:     []string{"net-only"},
			wantConfidence:     "low",
			wantExplanationSub: "Could not determine",
		},
		{
			name:         "only_network_constraints_matched",
			errorMessage: "connection timed out",
			constraints: []ConstraintInfo{
				{Name: "net1", Type: "NetworkEgress", Severity: "Critical"},
				{Name: "adm1", Type: "Admission", Severity: "Warning"},
			},
			wantMatchNames:     []string{"net1"},
			wantConfidence:     "high",
			wantExplanationSub: "network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, confidence, explanation := matchError(tt.errorMessage, tt.constraints)

			assert.Equal(t, tt.wantConfidence, confidence, "confidence mismatch")
			assert.Contains(t, explanation, tt.wantExplanationSub, "explanation mismatch")

			gotNames := make([]string, len(matches))
			for i, m := range matches {
				gotNames[i] = m.Name
			}

			if tt.wantMatchNames == nil {
				require.Nil(t, matches)
			} else {
				require.Len(t, matches, len(tt.wantMatchNames), "match count mismatch, got: %v", gotNames)
				for _, wantName := range tt.wantMatchNames {
					assert.Contains(t, gotNames, wantName, "expected match %q not found in %v", wantName, gotNames)
				}
			}
		})
	}
}
