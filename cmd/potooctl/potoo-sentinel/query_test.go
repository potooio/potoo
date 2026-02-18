package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestSafeString_KeyPresent(t *testing.T) {
	m := map[string]interface{}{
		"name": "test-constraint",
	}
	assert.Equal(t, "test-constraint", safeString(m, "name"))
}

func TestSafeString_KeyMissing(t *testing.T) {
	m := map[string]interface{}{}
	assert.Equal(t, "", safeString(m, "name"))
}

func TestSafeString_NonStringValue(t *testing.T) {
	m := map[string]interface{}{
		"count": 42,
	}
	assert.Equal(t, "", safeString(m, "count"))
}

func TestSafeString_NilValue(t *testing.T) {
	m := map[string]interface{}{
		"key": nil,
	}
	assert.Equal(t, "", safeString(m, "key"))
}

func TestParseConstraintMap_FullMap(t *testing.T) {
	cMap := map[string]interface{}{
		"name":     "deny-egress",
		"type":     "NetworkEgress",
		"severity": "Critical",
		"effect":   "Deny",
		"message":  "Egress traffic denied",
		"source":   "cilium",
		"remediation": map[string]interface{}{
			"summary": "Allow egress",
			"steps": []interface{}{
				map[string]interface{}{
					"type":              "kubectl",
					"description":       "Apply network policy",
					"command":           "kubectl apply -f allow.yaml",
					"requiresPrivilege": "admin",
				},
			},
		},
		"tags": []interface{}{"network", "egress"},
	}

	info := parseConstraintMap(cMap)

	assert.Equal(t, "deny-egress", info.Name)
	assert.Equal(t, "NetworkEgress", info.Type)
	assert.Equal(t, "Critical", info.Severity)
	assert.Equal(t, "Deny", info.Effect)
	assert.Equal(t, "Egress traffic denied", info.Message)
	assert.Equal(t, "cilium", info.Source)

	require.NotNil(t, info.Remediation)
	assert.Equal(t, "Allow egress", info.Remediation.Summary)
	require.Len(t, info.Remediation.Steps, 1)
	assert.Equal(t, "kubectl", info.Remediation.Steps[0].Type)
	assert.Equal(t, "Apply network policy", info.Remediation.Steps[0].Description)
	assert.Equal(t, "kubectl apply -f allow.yaml", info.Remediation.Steps[0].Command)
	assert.Equal(t, "admin", info.Remediation.Steps[0].RequiresPrivilege)

	require.Len(t, info.Tags, 2)
	assert.Equal(t, "network", info.Tags[0])
	assert.Equal(t, "egress", info.Tags[1])
}

func TestParseConstraintMap_PartialMap(t *testing.T) {
	cMap := map[string]interface{}{
		"name":     "require-labels",
		"severity": "Warning",
	}

	info := parseConstraintMap(cMap)

	assert.Equal(t, "require-labels", info.Name)
	assert.Equal(t, "", info.Type)
	assert.Equal(t, "Warning", info.Severity)
	assert.Equal(t, "", info.Effect)
	assert.Equal(t, "", info.Message)
	assert.Equal(t, "", info.Source)
	assert.Nil(t, info.Remediation)
	assert.Nil(t, info.Tags)
}

func TestParseConstraintMap_ConstraintTypeField(t *testing.T) {
	// When "type" is missing, it should fall back to "constraintType"
	cMap := map[string]interface{}{
		"name":           "policy-x",
		"constraintType": "Admission",
	}

	info := parseConstraintMap(cMap)

	assert.Equal(t, "Admission", info.Type)
}

func TestParseConstraintMap_EmptyMap(t *testing.T) {
	cMap := map[string]interface{}{}
	info := parseConstraintMap(cMap)

	assert.Equal(t, "", info.Name)
	assert.Equal(t, "", info.Type)
	assert.Equal(t, "", info.Severity)
	assert.Nil(t, info.Remediation)
	assert.Nil(t, info.Tags)
}

func TestParseConstraintMap_TagsWithNonStringEntries(t *testing.T) {
	cMap := map[string]interface{}{
		"name": "test",
		"tags": []interface{}{"valid-tag", 123, "another-tag"},
	}

	info := parseConstraintMap(cMap)

	// Only string tags should be included
	assert.Equal(t, []string{"valid-tag", "another-tag"}, info.Tags)
}

func TestParseConstraintMap_RemediationWithoutSteps(t *testing.T) {
	cMap := map[string]interface{}{
		"name": "test",
		"remediation": map[string]interface{}{
			"summary": "Do something",
		},
	}

	info := parseConstraintMap(cMap)

	require.NotNil(t, info.Remediation)
	assert.Equal(t, "Do something", info.Remediation.Summary)
	assert.Nil(t, info.Remediation.Steps)
}

func TestExtractConstraints_MachineReadablePath(t *testing.T) {
	report := &unstructured.Unstructured{
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
							"name":     "require-labels",
							"type":     "Admission",
							"severity": "Warning",
						},
					},
				},
			},
		},
	}

	results := extractConstraints(report, "", "", "")

	require.Len(t, results, 2)
	assert.Equal(t, "deny-egress", results[0].Name)
	assert.Equal(t, "require-labels", results[1].Name)
}

func TestExtractConstraints_FallbackToHumanReadable(t *testing.T) {
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"constraints": []interface{}{
					map[string]interface{}{
						"name":     "fallback-constraint",
						"type":     "ResourceLimit",
						"severity": "Info",
					},
				},
			},
		},
	}

	results := extractConstraints(report, "", "", "")

	require.Len(t, results, 1)
	assert.Equal(t, "fallback-constraint", results[0].Name)
	assert.Equal(t, "ResourceLimit", results[0].Type)
}

func TestExtractConstraints_TypeFilter(t *testing.T) {
	report := &unstructured.Unstructured{
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
							"name":     "require-labels",
							"type":     "Admission",
							"severity": "Warning",
						},
					},
				},
			},
		},
	}

	results := extractConstraints(report, "NetworkEgress", "", "")

	require.Len(t, results, 1)
	assert.Equal(t, "deny-egress", results[0].Name)
}

func TestExtractConstraints_SeverityFilter(t *testing.T) {
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"machineReadable": map[string]interface{}{
					"constraints": []interface{}{
						map[string]interface{}{
							"name":     "c1",
							"type":     "Admission",
							"severity": "Critical",
						},
						map[string]interface{}{
							"name":     "c2",
							"type":     "Admission",
							"severity": "Warning",
						},
					},
				},
			},
		},
	}

	results := extractConstraints(report, "", "Warning", "")

	require.Len(t, results, 1)
	assert.Equal(t, "c2", results[0].Name)
}

func TestExtractConstraints_BothFilters(t *testing.T) {
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"machineReadable": map[string]interface{}{
					"constraints": []interface{}{
						map[string]interface{}{
							"name":     "c1",
							"type":     "NetworkEgress",
							"severity": "Critical",
						},
						map[string]interface{}{
							"name":     "c2",
							"type":     "Admission",
							"severity": "Critical",
						},
						map[string]interface{}{
							"name":     "c3",
							"type":     "NetworkEgress",
							"severity": "Warning",
						},
					},
				},
			},
		},
	}

	results := extractConstraints(report, "NetworkEgress", "Critical", "")

	require.Len(t, results, 1)
	assert.Equal(t, "c1", results[0].Name)
}

func TestExtractConstraints_NoConstraints(t *testing.T) {
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{},
		},
	}

	results := extractConstraints(report, "", "", "")
	assert.Empty(t, results)
}

func TestExtractConstraints_MachineReadableNoConstraintsKey(t *testing.T) {
	// machineReadable exists but has no "constraints" key -- should fall through to human-readable
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"machineReadable": map[string]interface{}{
					"version": "v1",
				},
				"constraints": []interface{}{
					map[string]interface{}{
						"name":     "fallback",
						"type":     "Admission",
						"severity": "Info",
					},
				},
			},
		},
	}

	results := extractConstraints(report, "", "", "")

	require.Len(t, results, 1)
	assert.Equal(t, "fallback", results[0].Name)
}

func TestExtractConstraints_InvalidConstraintEntry(t *testing.T) {
	// Non-map entries in constraints list should be skipped
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"constraints": []interface{}{
					"not-a-map",
					map[string]interface{}{
						"name": "valid",
						"type": "Admission",
					},
					"also-not-a-map",
				},
			},
		},
	}

	results := extractConstraints(report, "", "", "")

	require.Len(t, results, 1)
	assert.Equal(t, "valid", results[0].Name)
}

func TestExtractConstraints_FallbackWithFilters(t *testing.T) {
	// Test filtering on the human-readable fallback path
	report := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": map[string]interface{}{
				"constraints": []interface{}{
					map[string]interface{}{
						"name":     "c1",
						"type":     "NetworkEgress",
						"severity": "Critical",
					},
					map[string]interface{}{
						"name":     "c2",
						"type":     "Admission",
						"severity": "Warning",
					},
				},
			},
		},
	}

	results := extractConstraints(report, "Admission", "Warning", "")

	require.Len(t, results, 1)
	assert.Equal(t, "c2", results[0].Name)
}
