package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	explainNamespace string
	explainWorkload  string
)

func explainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain [error-message]",
		Short: "Explain which constraint caused an error",
		Long: `Analyze an error message and identify matching constraints.

Examples:
  # Explain a connection error
  kubectl sentinel explain -n my-namespace "connection timed out"

  # Explain an admission error
  kubectl sentinel explain -n my-namespace "denied by policy"`,
		Args: cobra.ExactArgs(1),
		RunE: runExplain,
	}

	cmd.Flags().StringVarP(&explainNamespace, "namespace", "n", "", "Namespace context (required)")
	cmd.Flags().StringVar(&explainWorkload, "workload", "", "Optional workload name for context")
	cmd.MarkFlagRequired("namespace")

	return cmd
}

func runExplain(cmd *cobra.Command, args []string) error {
	errorMessage := args[0]

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

	report, err := client.Resource(gvr).Namespace(explainNamespace).Get(ctx, "constraints", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ConstraintReport: %w", err)
	}

	// Extract all constraints
	constraints := extractConstraints(report, "", "", "")

	// Match error to constraints
	matchingConstraints, confidence, explanation := matchError(errorMessage, constraints)

	result := ExplainResult{
		ErrorMessage:        errorMessage,
		Explanation:         explanation,
		Confidence:          confidence,
		MatchingConstraints: matchingConstraints,
	}

	// Collect remediation steps from matching constraints
	for _, c := range matchingConstraints {
		if c.Remediation != nil {
			result.RemediationSteps = append(result.RemediationSteps, c.Remediation.Steps...)
		}
	}

	return outputResult(result, outputFmt)
}

func matchError(errorMessage string, constraints []ConstraintInfo) ([]ConstraintInfo, string, string) {
	errorLower := strings.ToLower(errorMessage)

	var matches []ConstraintInfo
	confidence := "low"
	explanation := "No matching constraints found for this error message."

	// Network-related errors
	networkPatterns := []string{
		"connection refused", "connection timed out", "network unreachable",
		"no route to host", "dial tcp", "i/o timeout", "egress", "ingress",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(errorLower, pattern) {
			for _, c := range constraints {
				if c.Type == "NetworkIngress" || c.Type == "NetworkEgress" {
					matches = append(matches, c)
				}
			}
			if len(matches) > 0 {
				confidence = "high"
				explanation = "This error appears to be network-related. The following network policies may be blocking traffic."
			}
			break
		}
	}

	// Admission-related errors
	if len(matches) == 0 {
		admissionPatterns := []string{
			"denied", "rejected", "forbidden", "admission", "webhook",
			"not allowed", "policy violation", "constraint",
		}
		for _, pattern := range admissionPatterns {
			if strings.Contains(errorLower, pattern) {
				for _, c := range constraints {
					if c.Type == "Admission" {
						matches = append(matches, c)
					}
				}
				if len(matches) > 0 {
					confidence = "high"
					explanation = "This error appears to be from an admission controller. The following admission policies may be rejecting the request."
				}
				break
			}
		}
	}

	// Resource quota errors
	if len(matches) == 0 {
		quotaPatterns := []string{
			"exceeded quota", "resource quota", "limit exceeded", "insufficient",
			"cpu", "memory", "storage",
		}
		for _, pattern := range quotaPatterns {
			if strings.Contains(errorLower, pattern) {
				for _, c := range constraints {
					if c.Type == "ResourceLimit" {
						matches = append(matches, c)
					}
				}
				if len(matches) > 0 {
					confidence = "high"
					explanation = "This error appears to be quota-related. The following resource quotas may be limiting resources."
				}
				break
			}
		}
	}

	// If no matches, return all as low confidence
	if len(matches) == 0 {
		matches = constraints
		confidence = "low"
		explanation = "Could not determine the specific cause. Here are all constraints in the namespace that might be relevant."
	}

	return matches, confidence, explanation
}
