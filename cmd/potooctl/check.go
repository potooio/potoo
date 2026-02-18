package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

var (
	checkFile string
)

func checkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Pre-check whether a manifest would be blocked",
		Long: `Analyze a manifest and check for blocking constraints.

Examples:
  # Check a manifest file
  potoo check -f deployment.yaml

  # Check and output as JSON
  potoo check -f deployment.yaml -o json`,
		RunE: runCheck,
	}

	cmd.Flags().StringVarP(&checkFile, "filename", "f", "", "Manifest file to check (required)")
	cmd.MarkFlagRequired("filename")

	return cmd
}

func runCheck(cmd *cobra.Command, args []string) error {
	// Read manifest file
	data, err := os.ReadFile(checkFile)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse manifest
	var manifest map[string]interface{}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Extract namespace and labels
	metadata, _ := manifest["metadata"].(map[string]interface{})
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = "default"
	}

	name, _ := metadata["name"].(string)
	kind, _ := manifest["kind"].(string)

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

	report, err := client.Resource(gvr).Namespace(namespace).Get(ctx, "constraints", metav1.GetOptions{})
	if err != nil {
		// If no report exists, there are no constraints
		result := CheckResult{
			WouldBlock: false,
			Manifest: ManifestInfo{
				Kind:      kind,
				Name:      name,
				Namespace: namespace,
			},
		}
		return outputResult(result, outputFmt)
	}

	// Extract all constraints
	constraints := extractConstraints(report, "", "", "")

	// Check for blocking constraints
	var blocking []ConstraintInfo
	var warnings []string

	for _, c := range constraints {
		// Critical admission constraints are blocking
		if c.Type == "Admission" && c.Severity == "Critical" {
			blocking = append(blocking, c)
		} else if c.Severity == "Warning" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", c.Name, c.Message))
		}
	}

	result := CheckResult{
		WouldBlock:          len(blocking) > 0,
		BlockingConstraints: blocking,
		Warnings:            warnings,
		Manifest: ManifestInfo{
			Kind:      kind,
			Name:      name,
			Namespace: namespace,
		},
	}

	return outputResult(result, outputFmt)
}
