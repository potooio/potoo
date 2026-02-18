package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	queryNamespace      string
	queryConstraintType string
	querySeverity       string
	queryWorkload       string
)

func queryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query constraints affecting a namespace",
		Long: `Query constraints from ConstraintReport CRDs.

Examples:
  # Query all constraints in a namespace
  kubectl sentinel query -n my-namespace

  # Query with filters
  kubectl sentinel query -n my-namespace --type NetworkEgress --severity Critical

  # Output as JSON
  kubectl sentinel query -n my-namespace -o json`,
		RunE: runQuery,
	}

	cmd.Flags().StringVarP(&queryNamespace, "namespace", "n", "", "Namespace to query (required)")
	cmd.Flags().StringVar(&queryConstraintType, "type", "", "Filter by constraint type")
	cmd.Flags().StringVar(&querySeverity, "severity", "", "Filter by severity")
	cmd.Flags().StringVar(&queryWorkload, "workload", "", "Filter by workload name")
	cmd.MarkFlagRequired("namespace")

	return cmd
}

func runQuery(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()

	// Get the ConstraintReport for the namespace
	gvr := schema.GroupVersionResource{
		Group:    "potoo.io",
		Version:  "v1alpha1",
		Resource: "constraintreports",
	}

	report, err := client.Resource(gvr).Namespace(queryNamespace).Get(ctx, "constraints", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ConstraintReport: %w", err)
	}

	// Extract constraints from the report
	constraints := extractConstraints(report, queryConstraintType, querySeverity, queryWorkload)

	// Build result
	result := QueryResult{
		Namespace:   queryNamespace,
		Constraints: constraints,
		Total:       len(constraints),
	}

	return outputResult(result, outputFmt)
}

func extractConstraints(report *unstructured.Unstructured, typeFilter, severityFilter, workloadFilter string) []ConstraintInfo {
	var results []ConstraintInfo

	// Try machine-readable section first
	machineReadable, found, _ := unstructured.NestedMap(report.Object, "status", "machineReadable")
	if found && machineReadable != nil {
		constraintsList, found, _ := unstructured.NestedSlice(machineReadable, "constraints")
		if found {
			for _, c := range constraintsList {
				cMap, ok := c.(map[string]interface{})
				if !ok {
					continue
				}

				info := parseConstraintMap(cMap)

				// Apply filters
				if typeFilter != "" && info.Type != typeFilter {
					continue
				}
				if severityFilter != "" && info.Severity != severityFilter {
					continue
				}

				results = append(results, info)
			}
			return results
		}
	}

	// Fall back to human-readable constraints
	constraintsList, found, _ := unstructured.NestedSlice(report.Object, "status", "constraints")
	if !found {
		return results
	}

	for _, c := range constraintsList {
		cMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		info := parseConstraintMap(cMap)

		// Apply filters
		if typeFilter != "" && info.Type != typeFilter {
			continue
		}
		if severityFilter != "" && info.Severity != severityFilter {
			continue
		}

		results = append(results, info)
	}

	return results
}

func parseConstraintMap(cMap map[string]interface{}) ConstraintInfo {
	info := ConstraintInfo{}

	if name, ok := cMap["name"].(string); ok {
		info.Name = name
	}
	if t, ok := cMap["type"].(string); ok {
		info.Type = t
	} else if t, ok := cMap["constraintType"].(string); ok {
		info.Type = t
	}
	if severity, ok := cMap["severity"].(string); ok {
		info.Severity = severity
	}
	if effect, ok := cMap["effect"].(string); ok {
		info.Effect = effect
	}
	if message, ok := cMap["message"].(string); ok {
		info.Message = message
	}
	if source, ok := cMap["source"].(string); ok {
		info.Source = source
	}

	// Extract remediation if present
	if remedMap, ok := cMap["remediation"].(map[string]interface{}); ok {
		info.Remediation = &RemediationInfo{
			Summary: safeString(remedMap, "summary"),
		}
		if steps, ok := remedMap["steps"].([]interface{}); ok {
			for _, s := range steps {
				if stepMap, ok := s.(map[string]interface{}); ok {
					step := RemediationStep{
						Type:              safeString(stepMap, "type"),
						Description:       safeString(stepMap, "description"),
						Command:           safeString(stepMap, "command"),
						RequiresPrivilege: safeString(stepMap, "requiresPrivilege"),
					}
					info.Remediation.Steps = append(info.Remediation.Steps, step)
				}
			}
		}
	}

	// Extract tags if present
	if tags, ok := cMap["tags"].([]interface{}); ok {
		for _, t := range tags {
			if tag, ok := t.(string); ok {
				info.Tags = append(info.Tags, tag)
			}
		}
	}

	return info
}

func safeString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
