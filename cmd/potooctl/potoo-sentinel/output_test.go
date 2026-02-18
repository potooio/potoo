package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"text/tabwriter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout to capture output from functions that write to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	origStdout := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{name: "critical", severity: "critical", expected: "\033[31m"},
		{name: "Critical uppercase", severity: "Critical", expected: "\033[31m"},
		{name: "CRITICAL all caps", severity: "CRITICAL", expected: "\033[31m"},
		{name: "warning", severity: "warning", expected: "\033[33m"},
		{name: "Warning uppercase", severity: "Warning", expected: "\033[33m"},
		{name: "info", severity: "info", expected: "\033[36m"},
		{name: "Info uppercase", severity: "Info", expected: "\033[36m"},
		{name: "unknown severity", severity: "unknown", expected: ""},
		{name: "empty string", severity: "", expected: ""},
		{name: "arbitrary string", severity: "debug", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := severityColor(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestColorResetConstant(t *testing.T) {
	assert.Equal(t, "\033[0m", colorReset)
}

func TestOutputQueryTable(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := QueryResult{
		Namespace: "production",
		Total:     2,
		Constraints: []ConstraintInfo{
			{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical", Effect: "Deny", Source: "cilium"},
			{Name: "require-labels", Type: "Admission", Severity: "Warning", Effect: "Warn", Source: "gatekeeper"},
		},
	}

	err := outputQueryTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "NAMESPACE")
	assert.Contains(t, output, "production")
	assert.Contains(t, output, "TOTAL")
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "TYPE")
	assert.Contains(t, output, "SEVERITY")
	assert.Contains(t, output, "EFFECT")
	assert.Contains(t, output, "SOURCE")
	assert.Contains(t, output, "deny-egress")
	assert.Contains(t, output, "NetworkEgress")
	assert.Contains(t, output, "require-labels")
	assert.Contains(t, output, "gatekeeper")
}

func TestOutputQueryTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := QueryResult{
		Namespace:   "default",
		Total:       0,
		Constraints: nil,
	}

	err := outputQueryTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "NAMESPACE")
	assert.Contains(t, output, "default")
	assert.Contains(t, output, "TOTAL")
}

func TestOutputExplainTable(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := ExplainResult{
		ErrorMessage: "connection timed out",
		Confidence:   "high",
		Explanation:  "Network policy is blocking traffic",
		MatchingConstraints: []ConstraintInfo{
			{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
		},
		RemediationSteps: []RemediationStep{
			{Type: "manual", Description: "Add egress rule", Command: "kubectl apply -f egress.yaml"},
		},
	}

	err := outputExplainTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "ERROR:")
	assert.Contains(t, output, "connection timed out")
	assert.Contains(t, output, "CONFIDENCE:")
	assert.Contains(t, output, "high")
	assert.Contains(t, output, "EXPLANATION:")
	assert.Contains(t, output, "Network policy is blocking traffic")
	assert.Contains(t, output, "MATCHING CONSTRAINTS:")
	assert.Contains(t, output, "deny-egress")
	assert.Contains(t, output, "REMEDIATION STEPS:")
	assert.Contains(t, output, "Add egress rule")
	assert.Contains(t, output, "Command: kubectl apply -f egress.yaml")
}

func TestOutputExplainTable_NoConstraintsNoSteps(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := ExplainResult{
		ErrorMessage:        "some error",
		Confidence:          "low",
		Explanation:         "No match found",
		MatchingConstraints: nil,
		RemediationSteps:    nil,
	}

	err := outputExplainTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "some error")
	assert.NotContains(t, output, "MATCHING CONSTRAINTS:")
	assert.NotContains(t, output, "REMEDIATION STEPS:")
}

func TestOutputExplainTable_StepWithoutCommand(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := ExplainResult{
		ErrorMessage: "error",
		Confidence:   "low",
		Explanation:  "unknown",
		RemediationSteps: []RemediationStep{
			{Type: "manual", Description: "Contact admin", Command: ""},
		},
	}

	err := outputExplainTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "Contact admin")
	assert.NotContains(t, output, "Command:")
}

func TestOutputCheckTable_Pass(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := CheckResult{
		WouldBlock: false,
		Manifest: ManifestInfo{
			Kind:      "Deployment",
			Name:      "my-app",
			Namespace: "production",
		},
	}

	err := outputCheckTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "MANIFEST:")
	assert.Contains(t, output, "production/my-app (Deployment)")
	assert.Contains(t, output, "STATUS:")
	assert.Contains(t, output, "PASS")
	assert.NotContains(t, output, "BLOCKED")
}

func TestOutputCheckTable_Blocked(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := CheckResult{
		WouldBlock: true,
		Manifest: ManifestInfo{
			Kind:      "Deployment",
			Name:      "my-app",
			Namespace: "production",
		},
		BlockingConstraints: []ConstraintInfo{
			{Name: "no-privileged", Type: "Admission", Severity: "Critical"},
		},
		Warnings: []string{"Missing required labels"},
	}

	err := outputCheckTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "BLOCKED")
	assert.Contains(t, output, "BLOCKING CONSTRAINTS:")
	assert.Contains(t, output, "no-privileged")
	assert.Contains(t, output, "WARNINGS:")
	assert.Contains(t, output, "Missing required labels")
}

func TestOutputCheckTable_NoBlockingNoWarnings(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := CheckResult{
		WouldBlock:          false,
		BlockingConstraints: nil,
		Warnings:            nil,
		Manifest: ManifestInfo{
			Kind:      "Service",
			Name:      "my-svc",
			Namespace: "default",
		},
	}

	err := outputCheckTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "PASS")
	assert.NotContains(t, output, "BLOCKING CONSTRAINTS:")
	assert.NotContains(t, output, "WARNINGS:")
}

func TestOutputRemediateTable(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := RemediateResult{
		Constraint: ConstraintInfo{
			Name:     "deny-egress",
			Type:     "NetworkEgress",
			Severity: "Critical",
		},
		Summary: "Allow egress to external API",
		Steps: []RemediationStep{
			{
				Type:              "kubectl",
				Description:       "Apply network policy",
				Command:           "kubectl apply -f allow-egress.yaml",
				RequiresPrivilege: "admin",
			},
			{
				Type:        "manual",
				Description: "Verify connectivity",
			},
		},
	}

	err := outputRemediateTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "CONSTRAINT:")
	assert.Contains(t, output, "deny-egress (NetworkEgress)")
	assert.Contains(t, output, "SEVERITY:")
	assert.Contains(t, output, "Critical")
	assert.Contains(t, output, "SUMMARY:")
	assert.Contains(t, output, "Allow egress to external API")
	assert.Contains(t, output, "REMEDIATION STEPS:")
	assert.Contains(t, output, "[kubectl] (admin)")
	assert.Contains(t, output, "Apply network policy")
	assert.Contains(t, output, "$ kubectl apply -f allow-egress.yaml")
	assert.Contains(t, output, "[manual] (developer)") // default privilege
	assert.Contains(t, output, "Verify connectivity")
}

func TestOutputRemediateTable_NoSteps(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := RemediateResult{
		Constraint: ConstraintInfo{
			Name:     "test",
			Type:     "Admission",
			Severity: "Warning",
		},
		Summary: "No steps available",
		Steps:   nil,
	}

	err := outputRemediateTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "No steps available")
	assert.NotContains(t, output, "REMEDIATION STEPS:")
}

func TestOutputStatusTable(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := StatusResult{
		TotalConstraints: 15,
		NamespaceCount:   3,
		TotalCritical:    2,
		TotalWarning:     8,
		TotalInfo:        5,
		NamespaceSummaries: []NamespaceSummary{
			{Namespace: "production", Total: 10, CriticalCount: 2, WarningCount: 5, InfoCount: 3},
			{Namespace: "staging", Total: 3, CriticalCount: 0, WarningCount: 2, InfoCount: 1},
			{Namespace: "dev", Total: 2, CriticalCount: 0, WarningCount: 1, InfoCount: 1},
		},
	}

	err := outputStatusTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "TOTAL CONSTRAINTS:")
	assert.Contains(t, output, "15")
	assert.Contains(t, output, "NAMESPACES:")
	assert.Contains(t, output, "3")
	assert.Contains(t, output, "CRITICAL:")
	assert.Contains(t, output, "WARNING:")
	assert.Contains(t, output, "INFO:")
	assert.Contains(t, output, "NAMESPACE")
	assert.Contains(t, output, "production")
	assert.Contains(t, output, "staging")
	assert.Contains(t, output, "dev")
}

func TestOutputStatusTable_NoNamespaces(t *testing.T) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	r := StatusResult{
		TotalConstraints:   0,
		NamespaceCount:     0,
		NamespaceSummaries: nil,
	}

	err := outputStatusTable(w, r)
	require.NoError(t, err)
	w.Flush()

	output := buf.String()
	assert.Contains(t, output, "TOTAL CONSTRAINTS:")
	assert.NotContains(t, output, "NAMESPACE\tTOTAL")
}

func TestOutputJSON(t *testing.T) {
	r := QueryResult{
		Namespace: "test-ns",
		Total:     1,
		Constraints: []ConstraintInfo{
			{Name: "c1", Type: "Admission", Severity: "Warning"},
		},
	}

	output := captureStdout(t, func() {
		err := outputJSON(r)
		assert.NoError(t, err)
	})

	// Should be valid JSON
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "test-ns", parsed["namespace"])
	assert.Equal(t, float64(1), parsed["total"])
}

func TestOutputYAML(t *testing.T) {
	r := QueryResult{
		Namespace: "yaml-ns",
		Total:     0,
	}

	output := captureStdout(t, func() {
		err := outputYAML(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "namespace: yaml-ns")
}

func TestOutputTable_QueryResult(t *testing.T) {
	r := QueryResult{
		Namespace: "table-ns",
		Total:     1,
		Constraints: []ConstraintInfo{
			{Name: "c1", Type: "Admission", Severity: "Info", Effect: "Warn", Source: "gatekeeper"},
		},
	}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "NAMESPACE")
	assert.Contains(t, output, "table-ns")
	assert.Contains(t, output, "c1")
}

func TestOutputTable_ExplainResult(t *testing.T) {
	r := ExplainResult{
		ErrorMessage: "test error",
		Confidence:   "low",
		Explanation:  "unknown",
	}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "ERROR:")
	assert.Contains(t, output, "test error")
}

func TestOutputTable_CheckResult(t *testing.T) {
	r := CheckResult{
		WouldBlock: false,
		Manifest:   ManifestInfo{Kind: "Pod", Name: "test", Namespace: "default"},
	}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "PASS")
}

func TestOutputTable_RemediateResult(t *testing.T) {
	r := RemediateResult{
		Constraint: ConstraintInfo{Name: "c1", Type: "Admission", Severity: "Warning"},
		Summary:    "Fix it",
	}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "CONSTRAINT:")
	assert.Contains(t, output, "Fix it")
}

func TestOutputTable_StatusResult(t *testing.T) {
	r := StatusResult{
		TotalConstraints: 5,
		NamespaceCount:   2,
	}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "TOTAL CONSTRAINTS:")
}

func TestOutputTable_UnknownType(t *testing.T) {
	// Unknown type should fall back to JSON
	r := struct {
		Foo string `json:"foo"`
	}{Foo: "bar"}

	output := captureStdout(t, func() {
		err := outputTable(r)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "bar")
}

func TestOutputResult_JSONFormat(t *testing.T) {
	r := QueryResult{Namespace: "ns1", Total: 0}

	output := captureStdout(t, func() {
		err := outputResult(r, "json")
		assert.NoError(t, err)
	})

	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)
	assert.Equal(t, "ns1", parsed["namespace"])
}

func TestOutputResult_YAMLFormat(t *testing.T) {
	r := QueryResult{Namespace: "ns2", Total: 3}

	output := captureStdout(t, func() {
		err := outputResult(r, "yaml")
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "namespace: ns2")
	assert.Contains(t, output, "total: 3")
}

func TestOutputResult_DefaultTableFormat(t *testing.T) {
	r := StatusResult{TotalConstraints: 10, NamespaceCount: 1}

	output := captureStdout(t, func() {
		err := outputResult(r, "table")
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "TOTAL CONSTRAINTS:")
}

func TestOutputResult_UnknownFormatDefaultsToTable(t *testing.T) {
	r := StatusResult{TotalConstraints: 7}

	output := captureStdout(t, func() {
		err := outputResult(r, "unknown-format")
		assert.NoError(t, err)
	})

	// Default case falls through to outputTable
	assert.Contains(t, output, "TOTAL CONSTRAINTS:")
}
