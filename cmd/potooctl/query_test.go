package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ---------------------------------------------------------------------------
// safeString
// ---------------------------------------------------------------------------

func TestSafeString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want string
	}{
		{
			name: "key_exists_string",
			m:    map[string]interface{}{"name": "test"},
			key:  "name",
			want: "test",
		},
		{
			name: "key_missing",
			m:    map[string]interface{}{"other": "value"},
			key:  "name",
			want: "",
		},
		{
			name: "key_exists_non_string",
			m:    map[string]interface{}{"count": 42},
			key:  "count",
			want: "",
		},
		{
			name: "key_exists_nil",
			m:    map[string]interface{}{"name": nil},
			key:  "name",
			want: "",
		},
		{
			name: "empty_map",
			m:    map[string]interface{}{},
			key:  "name",
			want: "",
		},
		{
			name: "key_exists_empty_string",
			m:    map[string]interface{}{"name": ""},
			key:  "name",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeString(tt.m, tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// parseConstraintMap
// ---------------------------------------------------------------------------

func TestParseConstraintMap(t *testing.T) {
	tests := []struct {
		name string
		cMap map[string]interface{}
		want ConstraintInfo
	}{
		{
			name: "all_fields",
			cMap: map[string]interface{}{
				"name":     "deny-egress",
				"type":     "NetworkEgress",
				"severity": "Critical",
				"effect":   "Deny",
				"message":  "Egress blocked",
				"source":   "cilium",
			},
			want: ConstraintInfo{
				Name:     "deny-egress",
				Type:     "NetworkEgress",
				Severity: "Critical",
				Effect:   "Deny",
				Message:  "Egress blocked",
				Source:   "cilium",
			},
		},
		{
			name: "constraintType_fallback",
			cMap: map[string]interface{}{
				"name":           "policy-1",
				"constraintType": "Admission",
				"severity":       "Warning",
			},
			want: ConstraintInfo{
				Name:     "policy-1",
				Type:     "Admission",
				Severity: "Warning",
			},
		},
		{
			name: "type_takes_precedence_over_constraintType",
			cMap: map[string]interface{}{
				"name":           "c1",
				"type":           "NetworkIngress",
				"constraintType": "Admission",
			},
			want: ConstraintInfo{
				Name: "c1",
				Type: "NetworkIngress",
			},
		},
		{
			name: "empty_map",
			cMap: map[string]interface{}{},
			want: ConstraintInfo{},
		},
		{
			name: "non_string_values_ignored",
			cMap: map[string]interface{}{
				"name":     123,
				"type":     true,
				"severity": nil,
			},
			want: ConstraintInfo{},
		},
		{
			name: "with_remediation",
			cMap: map[string]interface{}{
				"name":     "quota-limit",
				"type":     "ResourceLimit",
				"severity": "Critical",
				"remediation": map[string]interface{}{
					"summary": "Increase quota",
					"steps": []interface{}{
						map[string]interface{}{
							"type":              "command",
							"description":       "Request quota increase",
							"command":           "kubectl edit quota",
							"requiresPrivilege": "admin",
						},
					},
				},
			},
			want: ConstraintInfo{
				Name:     "quota-limit",
				Type:     "ResourceLimit",
				Severity: "Critical",
				Remediation: &RemediationInfo{
					Summary: "Increase quota",
					Steps: []RemediationStep{
						{
							Type:              "command",
							Description:       "Request quota increase",
							Command:           "kubectl edit quota",
							RequiresPrivilege: "admin",
						},
					},
				},
			},
		},
		{
			name: "with_remediation_no_steps",
			cMap: map[string]interface{}{
				"name": "c1",
				"remediation": map[string]interface{}{
					"summary": "Do stuff",
				},
			},
			want: ConstraintInfo{
				Name: "c1",
				Remediation: &RemediationInfo{
					Summary: "Do stuff",
				},
			},
		},
		{
			name: "with_tags",
			cMap: map[string]interface{}{
				"name": "tagged",
				"tags": []interface{}{"network", "security"},
			},
			want: ConstraintInfo{
				Name: "tagged",
				Tags: []string{"network", "security"},
			},
		},
		{
			name: "tags_with_non_string_elements",
			cMap: map[string]interface{}{
				"name": "mixed-tags",
				"tags": []interface{}{"valid", 42, "also-valid"},
			},
			want: ConstraintInfo{
				Name: "mixed-tags",
				Tags: []string{"valid", "also-valid"},
			},
		},
		{
			name: "remediation_steps_with_invalid_entries",
			cMap: map[string]interface{}{
				"name": "c1",
				"remediation": map[string]interface{}{
					"summary": "fix it",
					"steps": []interface{}{
						"not-a-map",
						map[string]interface{}{
							"type":        "manual",
							"description": "Do the thing",
						},
					},
				},
			},
			want: ConstraintInfo{
				Name: "c1",
				Remediation: &RemediationInfo{
					Summary: "fix it",
					Steps: []RemediationStep{
						{Type: "manual", Description: "Do the thing"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseConstraintMap(tt.cMap)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// extractConstraints
// ---------------------------------------------------------------------------

func TestExtractConstraints(t *testing.T) {
	tests := []struct {
		name           string
		report         *unstructured.Unstructured
		typeFilter     string
		severityFilter string
		workloadFilter string
		wantCount      int
		verify         func(t *testing.T, results []ConstraintInfo)
	}{
		{
			name: "machine_readable_path",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								map[string]interface{}{
									"name":     "deny-egress",
									"type":     "NetworkEgress",
									"severity": "Critical",
								},
								map[string]interface{}{
									"name":     "limit-cpu",
									"type":     "ResourceLimit",
									"severity": "Warning",
								},
							},
						},
					},
				},
			},
			wantCount: 2,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "deny-egress", results[0].Name)
				assert.Equal(t, "limit-cpu", results[1].Name)
			},
		},
		{
			name: "fallback_to_status_constraints",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"constraints": []interface{}{
							map[string]interface{}{
								"name":     "fallback-c1",
								"type":     "Admission",
								"severity": "Warning",
							},
						},
					},
				},
			},
			wantCount: 1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "fallback-c1", results[0].Name)
			},
		},
		{
			name: "type_filter",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								map[string]interface{}{
									"name": "c1", "type": "NetworkEgress", "severity": "Critical",
								},
								map[string]interface{}{
									"name": "c2", "type": "Admission", "severity": "Warning",
								},
								map[string]interface{}{
									"name": "c3", "type": "NetworkEgress", "severity": "Warning",
								},
							},
						},
					},
				},
			},
			typeFilter: "NetworkEgress",
			wantCount:  2,
			verify: func(t *testing.T, results []ConstraintInfo) {
				for _, r := range results {
					assert.Equal(t, "NetworkEgress", r.Type)
				}
			},
		},
		{
			name: "severity_filter",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								map[string]interface{}{
									"name": "c1", "type": "NetworkEgress", "severity": "Critical",
								},
								map[string]interface{}{
									"name": "c2", "type": "Admission", "severity": "Warning",
								},
							},
						},
					},
				},
			},
			severityFilter: "Critical",
			wantCount:      1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "c1", results[0].Name)
				assert.Equal(t, "Critical", results[0].Severity)
			},
		},
		{
			name: "combined_filters",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								map[string]interface{}{
									"name": "c1", "type": "NetworkEgress", "severity": "Critical",
								},
								map[string]interface{}{
									"name": "c2", "type": "NetworkEgress", "severity": "Warning",
								},
								map[string]interface{}{
									"name": "c3", "type": "Admission", "severity": "Critical",
								},
							},
						},
					},
				},
			},
			typeFilter:     "NetworkEgress",
			severityFilter: "Critical",
			wantCount:      1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "c1", results[0].Name)
			},
		},
		{
			name: "filter_excludes_all",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								map[string]interface{}{
									"name": "c1", "type": "Admission", "severity": "Warning",
								},
							},
						},
					},
				},
			},
			typeFilter: "NetworkEgress",
			wantCount:  0,
		},
		{
			name: "empty_status",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{},
				},
			},
			wantCount: 0,
		},
		{
			name: "no_status_key",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"name": "report"},
				},
			},
			wantCount: 0,
		},
		{
			name: "machine_readable_empty_constraints",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{},
						},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "invalid_constraint_entries_skipped",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"constraints": []interface{}{
								"not-a-map",
								float64(42),
								map[string]interface{}{
									"name": "valid", "type": "Admission", "severity": "Info",
								},
							},
						},
					},
				},
			},
			wantCount: 1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "valid", results[0].Name)
			},
		},
		{
			name: "fallback_path_with_type_filter",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"constraints": []interface{}{
							map[string]interface{}{
								"name": "fb1", "type": "Admission", "severity": "Warning",
							},
							map[string]interface{}{
								"name": "fb2", "type": "NetworkEgress", "severity": "Critical",
							},
						},
					},
				},
			},
			typeFilter: "Admission",
			wantCount:  1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "fb1", results[0].Name)
			},
		},
		{
			name: "fallback_path_with_severity_filter",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"constraints": []interface{}{
							map[string]interface{}{
								"name": "fb1", "type": "Admission", "severity": "Warning",
							},
							map[string]interface{}{
								"name": "fb2", "type": "NetworkEgress", "severity": "Critical",
							},
						},
					},
				},
			},
			severityFilter: "Critical",
			wantCount:      1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "fb2", results[0].Name)
			},
		},
		{
			name: "machine_readable_present_but_no_constraints_key",
			report: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"status": map[string]interface{}{
						"machineReadable": map[string]interface{}{
							"otherField": "something",
						},
						// fallback constraints
						"constraints": []interface{}{
							map[string]interface{}{
								"name": "fb-c1", "type": "Admission", "severity": "Info",
							},
						},
					},
				},
			},
			wantCount: 1,
			verify: func(t *testing.T, results []ConstraintInfo) {
				assert.Equal(t, "fb-c1", results[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := extractConstraints(tt.report, tt.typeFilter, tt.severityFilter, tt.workloadFilter)
			require.Len(t, results, tt.wantCount)
			if tt.verify != nil {
				tt.verify(t, results)
			}
		})
	}
}
