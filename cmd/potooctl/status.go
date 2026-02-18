package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show overall constraint status across namespaces",
		Long: `Show a summary of constraints across all accessible namespaces.

Examples:
  # Show status
  potoo status

  # Output as JSON
  potoo status -o json`,
		RunE: runStatus,
	}

	return cmd
}

func runStatus(cmd *cobra.Command, args []string) error {
	client, err := getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()

	// List all ConstraintReports
	gvr := schema.GroupVersionResource{
		Group:    "potoo.io",
		Version:  "v1alpha1",
		Resource: "constraintreports",
	}

	reports, err := client.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list ConstraintReports: %w", err)
	}

	var summaries []NamespaceSummary
	var totalConstraints, totalCritical, totalWarning, totalInfo int

	for _, report := range reports.Items {
		ns := report.GetNamespace()

		// Extract counts from status
		constraintCount, _, _ := getInt64(report.Object, "status", "constraintCount")
		criticalCount, _, _ := getInt64(report.Object, "status", "criticalCount")
		warningCount, _, _ := getInt64(report.Object, "status", "warningCount")
		infoCount, _, _ := getInt64(report.Object, "status", "infoCount")

		totalConstraints += int(constraintCount)
		totalCritical += int(criticalCount)
		totalWarning += int(warningCount)
		totalInfo += int(infoCount)

		summary := NamespaceSummary{
			Namespace:     ns,
			Total:         int(constraintCount),
			CriticalCount: int(criticalCount),
			WarningCount:  int(warningCount),
			InfoCount:     int(infoCount),
		}

		summaries = append(summaries, summary)
	}

	result := StatusResult{
		NamespaceSummaries: summaries,
		TotalConstraints:   totalConstraints,
		TotalCritical:      totalCritical,
		TotalWarning:       totalWarning,
		TotalInfo:          totalInfo,
		NamespaceCount:     len(summaries),
	}

	return outputResult(result, outputFmt)
}

func getInt64(obj map[string]interface{}, fields ...string) (int64, bool, error) {
	current := obj
	for i, field := range fields {
		if i == len(fields)-1 {
			// Last field, extract value
			switch v := current[field].(type) {
			case int64:
				return v, true, nil
			case float64:
				return int64(v), true, nil
			case int:
				return int64(v), true, nil
			default:
				return 0, false, nil
			}
		}
		// Navigate into nested map
		next, ok := current[field].(map[string]interface{})
		if !ok {
			return 0, false, nil
		}
		current = next
	}
	return 0, false, nil
}
