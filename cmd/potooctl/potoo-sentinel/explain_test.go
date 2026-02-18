package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchError_NetworkError(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
		{Name: "deny-ingress", Type: "NetworkIngress", Severity: "Warning"},
		{Name: "require-labels", Type: "Admission", Severity: "Info"},
	}

	matches, confidence, explanation := matchError("connection timed out", constraints)

	assert.Equal(t, "high", confidence)
	assert.Contains(t, explanation, "network-related")
	require.Len(t, matches, 2)
	assert.Equal(t, "deny-egress", matches[0].Name)
	assert.Equal(t, "deny-ingress", matches[1].Name)
}

func TestMatchError_NetworkError_ConnectionRefused(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "net-policy", Type: "NetworkEgress", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("connection refused to backend:8080", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
	assert.Equal(t, "net-policy", matches[0].Name)
}

func TestMatchError_NetworkError_DialTCP(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "ingress-rule", Type: "NetworkIngress", Severity: "Warning"},
	}

	matches, confidence, _ := matchError("dial tcp 10.0.0.1:443: i/o timeout", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_AdmissionError(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
		{Name: "no-privileged", Type: "Admission", Severity: "Critical"},
	}

	matches, confidence, explanation := matchError("request denied by webhook", constraints)

	assert.Equal(t, "high", confidence)
	assert.Contains(t, explanation, "admission")
	require.Len(t, matches, 1)
	assert.Equal(t, "no-privileged", matches[0].Name)
}

func TestMatchError_AdmissionError_Forbidden(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "admission-policy", Type: "Admission", Severity: "Warning"},
	}

	matches, confidence, _ := matchError("forbidden: policy violation detected", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_AdmissionError_PolicyViolation(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "policy-1", Type: "Admission", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("policy violation: containers must not run as root", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_QuotaError(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
		{Name: "cpu-limit", Type: "ResourceLimit", Severity: "Warning"},
	}

	matches, confidence, explanation := matchError("exceeded quota for cpu", constraints)

	assert.Equal(t, "high", confidence)
	assert.Contains(t, explanation, "quota-related")
	require.Len(t, matches, 1)
	assert.Equal(t, "cpu-limit", matches[0].Name)
}

func TestMatchError_QuotaError_Memory(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "mem-limit", Type: "ResourceLimit", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("memory limit exceeded in namespace default", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_QuotaError_InsufficientResources(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "quota", Type: "ResourceLimit", Severity: "Warning"},
	}

	matches, confidence, _ := matchError("insufficient cpu to schedule pod", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_NoMatch(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "constraint-a", Type: "Admission", Severity: "Info"},
		{Name: "constraint-b", Type: "NetworkEgress", Severity: "Warning"},
	}

	matches, confidence, explanation := matchError("unknown error happened", constraints)

	assert.Equal(t, "low", confidence)
	assert.Contains(t, explanation, "Could not determine")
	// When no specific match, all constraints are returned
	require.Len(t, matches, 2)
}

func TestMatchError_NoConstraints(t *testing.T) {
	var constraints []ConstraintInfo

	matches, confidence, _ := matchError("connection refused", constraints)

	assert.Equal(t, "low", confidence)
	assert.Empty(t, matches)
}

func TestMatchError_CaseInsensitive(t *testing.T) {
	constraints := []ConstraintInfo{
		{Name: "net", Type: "NetworkEgress", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("CONNECTION TIMED OUT", constraints)

	assert.Equal(t, "high", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_NetworkNoMatchingType(t *testing.T) {
	// Network error pattern matches, but no network-type constraints exist
	constraints := []ConstraintInfo{
		{Name: "admission-only", Type: "Admission", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("connection refused", constraints)

	// No network constraints match, so it falls through to the "no matches" path
	// which returns all constraints with low confidence
	assert.Equal(t, "low", confidence)
	require.Len(t, matches, 1)
	assert.Equal(t, "admission-only", matches[0].Name)
}

func TestMatchError_AdmissionNoMatchingType(t *testing.T) {
	// Admission error pattern matches, but no admission-type constraints exist
	constraints := []ConstraintInfo{
		{Name: "network-only", Type: "NetworkEgress", Severity: "Critical"},
	}

	matches, confidence, _ := matchError("request denied by policy", constraints)

	// Falls through to quota check, then to "no matches"
	assert.Equal(t, "low", confidence)
	require.Len(t, matches, 1)
}

func TestMatchError_QuotaNoMatchingType(t *testing.T) {
	// Quota error pattern matches, but no resource-limit constraints exist
	constraints := []ConstraintInfo{
		{Name: "network-only", Type: "NetworkEgress", Severity: "Warning"},
	}

	matches, confidence, _ := matchError("exceeded quota", constraints)

	assert.Equal(t, "low", confidence)
	require.Len(t, matches, 1)
}
