package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// whatever was written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	r.Close()

	return buf.String()
}

// ---------------------------------------------------------------------------
// severityColor
// ---------------------------------------------------------------------------

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{name: "critical", severity: "critical", want: "\033[31m"},
		{name: "Critical_mixed_case", severity: "Critical", want: "\033[31m"},
		{name: "CRITICAL_upper", severity: "CRITICAL", want: "\033[31m"},
		{name: "warning", severity: "warning", want: "\033[33m"},
		{name: "Warning_mixed", severity: "Warning", want: "\033[33m"},
		{name: "info", severity: "info", want: "\033[36m"},
		{name: "Info_mixed", severity: "Info", want: "\033[36m"},
		{name: "unknown", severity: "debug", want: ""},
		{name: "empty", severity: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityColor(tt.severity)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// outputJSON
// ---------------------------------------------------------------------------

func TestOutputJSON(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		verify func(t *testing.T, output string)
	}{
		{
			name: "query_result",
			input: QueryResult{
				Namespace: "test-ns",
				Total:     1,
				Constraints: []ConstraintInfo{
					{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
				},
			},
			verify: func(t *testing.T, output string) {
				var decoded QueryResult
				require.NoError(t, json.Unmarshal([]byte(output), &decoded))
				assert.Equal(t, "test-ns", decoded.Namespace)
				assert.Equal(t, 1, decoded.Total)
				require.Len(t, decoded.Constraints, 1)
				assert.Equal(t, "deny-egress", decoded.Constraints[0].Name)
			},
		},
		{
			name:  "empty_struct",
			input: QueryResult{},
			verify: func(t *testing.T, output string) {
				var decoded QueryResult
				require.NoError(t, json.Unmarshal([]byte(output), &decoded))
				assert.Empty(t, decoded.Namespace)
				assert.Equal(t, 0, decoded.Total)
			},
		},
		{
			name:  "string_value",
			input: "hello",
			verify: func(t *testing.T, output string) {
				assert.Contains(t, output, "hello")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				err := outputJSON(tt.input)
				require.NoError(t, err)
			})
			tt.verify(t, output)
		})
	}
}

// ---------------------------------------------------------------------------
// outputYAML
// ---------------------------------------------------------------------------

func TestOutputYAML(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		verify func(t *testing.T, output string)
	}{
		{
			name: "query_result",
			input: QueryResult{
				Namespace: "prod",
				Total:     2,
				Constraints: []ConstraintInfo{
					{Name: "c1", Type: "Admission", Severity: "Warning"},
					{Name: "c2", Type: "NetworkEgress", Severity: "Critical"},
				},
			},
			verify: func(t *testing.T, output string) {
				assert.Contains(t, output, "namespace: prod")
				assert.Contains(t, output, "total: 2")
				assert.Contains(t, output, "name: c1")
				assert.Contains(t, output, "name: c2")
			},
		},
		{
			name: "status_result",
			input: StatusResult{
				TotalConstraints: 5,
				NamespaceCount:   2,
			},
			verify: func(t *testing.T, output string) {
				assert.Contains(t, output, "totalConstraints: 5")
				assert.Contains(t, output, "namespaceCount: 2")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				err := outputYAML(tt.input)
				require.NoError(t, err)
			})
			tt.verify(t, output)
		})
	}
}

// ---------------------------------------------------------------------------
// outputResult dispatching
// ---------------------------------------------------------------------------

func TestOutputResult(t *testing.T) {
	result := QueryResult{
		Namespace: "ns1",
		Total:     1,
		Constraints: []ConstraintInfo{
			{Name: "c1", Type: "Admission", Severity: "Critical"},
		},
	}

	t.Run("json_format", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputResult(result, "json")
			require.NoError(t, err)
		})
		var decoded QueryResult
		require.NoError(t, json.Unmarshal([]byte(output), &decoded))
		assert.Equal(t, "ns1", decoded.Namespace)
	})

	t.Run("yaml_format", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputResult(result, "yaml")
			require.NoError(t, err)
		})
		assert.Contains(t, output, "namespace: ns1")
	})

	t.Run("table_format", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputResult(result, "table")
			require.NoError(t, err)
		})
		assert.Contains(t, output, "NAMESPACE")
		assert.Contains(t, output, "ns1")
	})

	t.Run("default_is_table", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputResult(result, "")
			require.NoError(t, err)
		})
		assert.Contains(t, output, "NAMESPACE")
	})
}

// ---------------------------------------------------------------------------
// outputTable type dispatch
// ---------------------------------------------------------------------------

func TestOutputTableDispatch(t *testing.T) {
	t.Run("query_result", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(QueryResult{Namespace: "ns", Total: 0})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "NAMESPACE")
	})

	t.Run("explain_result", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(ExplainResult{
				ErrorMessage: "timeout",
				Confidence:   "high",
				Explanation:  "network issue",
			})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "ERROR:")
		assert.Contains(t, output, "CONFIDENCE:")
	})

	t.Run("check_result", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(CheckResult{
				WouldBlock: true,
				Manifest:   ManifestInfo{Kind: "Deployment", Name: "web", Namespace: "prod"},
			})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "MANIFEST:")
		assert.Contains(t, output, "STATUS:")
	})

	t.Run("remediate_result", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(RemediateResult{
				Constraint: ConstraintInfo{Name: "c1", Type: "Admission"},
				Summary:    "fix it",
			})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "CONSTRAINT:")
	})

	t.Run("status_result", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(StatusResult{TotalConstraints: 10, NamespaceCount: 3})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "TOTAL CONSTRAINTS:")
	})

	t.Run("unknown_type_falls_back_to_json", func(t *testing.T) {
		output := captureStdout(t, func() {
			err := outputTable(map[string]string{"foo": "bar"})
			require.NoError(t, err)
		})
		assert.Contains(t, output, "foo")
		assert.Contains(t, output, "bar")
	})
}

// ---------------------------------------------------------------------------
// outputQueryTable
// ---------------------------------------------------------------------------

func TestOutputQueryTable(t *testing.T) {
	tests := []struct {
		name   string
		result QueryResult
		check  func(t *testing.T, output string)
	}{
		{
			name: "with_constraints",
			result: QueryResult{
				Namespace: "test-ns",
				Total:     2,
				Constraints: []ConstraintInfo{
					{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical", Effect: "Deny", Source: "cilium"},
					{Name: "rate-limit", Type: "Admission", Severity: "Warning", Effect: "Warn", Source: "gatekeeper"},
				},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "test-ns")
				assert.Contains(t, output, "2")
				assert.Contains(t, output, "deny-egress")
				assert.Contains(t, output, "rate-limit")
				assert.Contains(t, output, "NAME")
				assert.Contains(t, output, "TYPE")
				assert.Contains(t, output, "SEVERITY")
				assert.Contains(t, output, "EFFECT")
				assert.Contains(t, output, "SOURCE")
			},
		},
		{
			name: "empty_constraints",
			result: QueryResult{
				Namespace:   "empty-ns",
				Total:       0,
				Constraints: nil,
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "empty-ns")
				assert.Contains(t, output, "0")
				assert.Contains(t, output, "NAME")
				assert.Contains(t, output, "SEVERITY")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			err := outputQueryTable(w, tt.result)
			require.NoError(t, err)
			w.Flush()
			tt.check(t, buf.String())
		})
	}
}

// ---------------------------------------------------------------------------
// outputExplainTable
// ---------------------------------------------------------------------------

func TestOutputExplainTable(t *testing.T) {
	tests := []struct {
		name   string
		result ExplainResult
		check  func(t *testing.T, output string)
	}{
		{
			name: "with_constraints_and_remediation",
			result: ExplainResult{
				ErrorMessage: "connection refused",
				Confidence:   "high",
				Explanation:  "network policy blocking",
				MatchingConstraints: []ConstraintInfo{
					{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
				},
				RemediationSteps: []RemediationStep{
					{Type: "command", Description: "Add network policy", Command: "kubectl apply -f np.yaml"},
				},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "connection refused")
				assert.Contains(t, output, "high")
				assert.Contains(t, output, "network policy blocking")
				assert.Contains(t, output, "MATCHING CONSTRAINTS:")
				assert.Contains(t, output, "deny-egress")
				assert.Contains(t, output, "REMEDIATION STEPS:")
				assert.Contains(t, output, "kubectl apply -f np.yaml")
			},
		},
		{
			name: "no_constraints_no_remediation",
			result: ExplainResult{
				ErrorMessage: "unknown error",
				Confidence:   "low",
				Explanation:  "no match",
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "unknown error")
				assert.Contains(t, output, "low")
				assert.NotContains(t, output, "MATCHING CONSTRAINTS:")
				assert.NotContains(t, output, "REMEDIATION STEPS:")
			},
		},
		{
			name: "remediation_without_command",
			result: ExplainResult{
				ErrorMessage: "err",
				Confidence:   "medium",
				Explanation:  "maybe",
				RemediationSteps: []RemediationStep{
					{Type: "manual", Description: "Contact admin"},
				},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "Contact admin")
				assert.NotContains(t, output, "Command:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			err := outputExplainTable(w, tt.result)
			require.NoError(t, err)
			w.Flush()
			tt.check(t, buf.String())
		})
	}
}

// ---------------------------------------------------------------------------
// outputCheckTable
// ---------------------------------------------------------------------------

func TestOutputCheckTable(t *testing.T) {
	tests := []struct {
		name   string
		result CheckResult
		check  func(t *testing.T, output string)
	}{
		{
			name: "blocked",
			result: CheckResult{
				WouldBlock: true,
				Manifest:   ManifestInfo{Kind: "Deployment", Name: "web", Namespace: "prod"},
				BlockingConstraints: []ConstraintInfo{
					{Name: "deny-all", Type: "Admission", Severity: "Critical"},
				},
				Warnings: []string{"resource limit close to quota"},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "BLOCKED")
				assert.Contains(t, output, "prod/web (Deployment)")
				assert.Contains(t, output, "BLOCKING CONSTRAINTS:")
				assert.Contains(t, output, "deny-all")
				assert.Contains(t, output, "WARNINGS:")
				assert.Contains(t, output, "resource limit close to quota")
			},
		},
		{
			name: "pass",
			result: CheckResult{
				WouldBlock: false,
				Manifest:   ManifestInfo{Kind: "Service", Name: "api", Namespace: "dev"},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "PASS")
				assert.Contains(t, output, "dev/api (Service)")
				assert.NotContains(t, output, "BLOCKING CONSTRAINTS:")
				assert.NotContains(t, output, "WARNINGS:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			err := outputCheckTable(w, tt.result)
			require.NoError(t, err)
			w.Flush()
			tt.check(t, buf.String())
		})
	}
}

// ---------------------------------------------------------------------------
// outputRemediateTable
// ---------------------------------------------------------------------------

func TestOutputRemediateTable(t *testing.T) {
	tests := []struct {
		name   string
		result RemediateResult
		check  func(t *testing.T, output string)
	}{
		{
			name: "with_steps_and_command",
			result: RemediateResult{
				Constraint: ConstraintInfo{Name: "deny-egress", Type: "NetworkEgress", Severity: "Critical"},
				Summary:    "Allow egress traffic",
				Steps: []RemediationStep{
					{Type: "command", Description: "Apply network policy", Command: "kubectl apply -f np.yaml", RequiresPrivilege: "admin"},
					{Type: "manual", Description: "Verify connectivity"},
				},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "deny-egress (NetworkEgress)")
				assert.Contains(t, output, "Critical")
				assert.Contains(t, output, "Allow egress traffic")
				assert.Contains(t, output, "REMEDIATION STEPS:")
				assert.Contains(t, output, "[command] (admin)")
				assert.Contains(t, output, "kubectl apply -f np.yaml")
				// default privilege
				assert.Contains(t, output, "[manual] (developer)")
			},
		},
		{
			name: "no_steps",
			result: RemediateResult{
				Constraint: ConstraintInfo{Name: "c1", Type: "Admission"},
				Summary:    "Contact admin",
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "c1 (Admission)")
				assert.Contains(t, output, "Contact admin")
				assert.NotContains(t, output, "REMEDIATION STEPS:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			err := outputRemediateTable(w, tt.result)
			require.NoError(t, err)
			w.Flush()
			tt.check(t, buf.String())
		})
	}
}

// ---------------------------------------------------------------------------
// outputStatusTable
// ---------------------------------------------------------------------------

func TestOutputStatusTable(t *testing.T) {
	tests := []struct {
		name   string
		result StatusResult
		check  func(t *testing.T, output string)
	}{
		{
			name: "with_summaries",
			result: StatusResult{
				TotalConstraints: 15,
				TotalCritical:    3,
				TotalWarning:     7,
				TotalInfo:        5,
				NamespaceCount:   2,
				NamespaceSummaries: []NamespaceSummary{
					{Namespace: "prod", Total: 10, CriticalCount: 2, WarningCount: 5, InfoCount: 3},
					{Namespace: "dev", Total: 5, CriticalCount: 1, WarningCount: 2, InfoCount: 2},
				},
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "TOTAL CONSTRAINTS:")
				assert.Contains(t, output, "15")
				assert.Contains(t, output, "NAMESPACES:")
				assert.Contains(t, output, "2")
				assert.Contains(t, output, "prod")
				assert.Contains(t, output, "dev")
				// Header row for namespace summaries (tabs replaced by spaces after flush)
				assert.Contains(t, output, "NAMESPACE")
				assert.Contains(t, output, "TOTAL")
				assert.Contains(t, output, "CRITICAL")
				assert.Contains(t, output, "WARNING")
				assert.Contains(t, output, "INFO")
			},
		},
		{
			name: "no_summaries",
			result: StatusResult{
				TotalConstraints: 0,
				NamespaceCount:   0,
			},
			check: func(t *testing.T, output string) {
				assert.Contains(t, output, "TOTAL CONSTRAINTS:")
				assert.Contains(t, output, "0")
				// Should not contain the per-namespace header when there are no summaries
				lines := strings.Split(output, "\n")
				foundHeader := false
				for _, l := range lines {
					if strings.Contains(l, "NAMESPACE\tTOTAL") || strings.Contains(l, "NAMESPACE") && strings.Contains(l, "CRITICAL") {
						foundHeader = true
					}
				}
				assert.False(t, foundHeader, "should not print namespace header with no summaries")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			err := outputStatusTable(w, tt.result)
			require.NoError(t, err)
			w.Flush()
			tt.check(t, buf.String())
		})
	}
}
