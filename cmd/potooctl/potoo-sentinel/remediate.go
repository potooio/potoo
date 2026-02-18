package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	remediateNamespace string
)

func remediateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediate [constraint-name]",
		Short: "Get detailed remediation for a constraint",
		Long: `Get structured remediation steps for a specific constraint.

Examples:
  # Get remediation for a constraint
  kubectl sentinel remediate -n my-namespace restrict-egress

  # Output as JSON
  kubectl sentinel remediate -n my-namespace restrict-egress -o json`,
		Args: cobra.ExactArgs(1),
		RunE: runRemediate,
	}

	cmd.Flags().StringVarP(&remediateNamespace, "namespace", "n", "", "Namespace of the constraint (required)")
	cmd.MarkFlagRequired("namespace")

	return cmd
}

func runRemediate(cmd *cobra.Command, args []string) error {
	constraintName := args[0]

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

	report, err := client.Resource(gvr).Namespace(remediateNamespace).Get(ctx, "constraints", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get ConstraintReport: %w", err)
	}

	// Extract all constraints
	constraints := extractConstraints(report, "", "", "")

	// Find the target constraint
	var target *ConstraintInfo
	for _, c := range constraints {
		if c.Name == constraintName {
			target = &c
			break
		}
	}

	if target == nil {
		return fmt.Errorf("constraint %q not found in namespace %q", constraintName, remediateNamespace)
	}

	// Build remediation result
	result := RemediateResult{
		Constraint: *target,
	}

	if target.Remediation != nil {
		result.Summary = target.Remediation.Summary
		result.Steps = target.Remediation.Steps
	} else {
		// Generate basic remediation if not present
		result.Summary = fmt.Sprintf("Contact your platform team about constraint %q", constraintName)
		result.Steps = []RemediationStep{
			{
				Type:              "manual",
				Description:       "Contact your platform team for assistance with this constraint",
				RequiresPrivilege: "developer",
			},
		}
	}

	return outputResult(result, outputFmt)
}
