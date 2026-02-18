package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

// Result types that match MCP schemas

// QueryResult is the result of a query command.
type QueryResult struct {
	Namespace   string           `json:"namespace"`
	Constraints []ConstraintInfo `json:"constraints"`
	Total       int              `json:"total"`
}

// ConstraintInfo represents a constraint in query results.
type ConstraintInfo struct {
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Severity    string           `json:"severity"`
	Effect      string           `json:"effect,omitempty"`
	Message     string           `json:"message,omitempty"`
	Source      string           `json:"source,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	Remediation *RemediationInfo `json:"remediation,omitempty"`
}

// RemediationInfo contains remediation data.
type RemediationInfo struct {
	Summary string            `json:"summary"`
	Steps   []RemediationStep `json:"steps,omitempty"`
}

// RemediationStep is a single remediation action.
type RemediationStep struct {
	Type              string `json:"type"`
	Description       string `json:"description"`
	Command           string `json:"command,omitempty"`
	RequiresPrivilege string `json:"requiresPrivilege,omitempty"`
}

// ExplainResult is the result of an explain command.
type ExplainResult struct {
	ErrorMessage        string            `json:"errorMessage"`
	Explanation         string            `json:"explanation"`
	Confidence          string            `json:"confidence"`
	MatchingConstraints []ConstraintInfo  `json:"matchingConstraints"`
	RemediationSteps    []RemediationStep `json:"remediationSteps,omitempty"`
}

// CheckResult is the result of a check command.
type CheckResult struct {
	WouldBlock          bool             `json:"wouldBlock"`
	BlockingConstraints []ConstraintInfo `json:"blockingConstraints,omitempty"`
	Warnings            []string         `json:"warnings,omitempty"`
	Manifest            ManifestInfo     `json:"manifest"`
}

// ManifestInfo describes the checked manifest.
type ManifestInfo struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// RemediateResult is the result of a remediate command.
type RemediateResult struct {
	Constraint ConstraintInfo    `json:"constraint"`
	Summary    string            `json:"summary"`
	Steps      []RemediationStep `json:"steps"`
}

// NamespaceSummary summarizes constraints in a namespace.
type NamespaceSummary struct {
	Namespace     string `json:"namespace"`
	Total         int    `json:"total"`
	CriticalCount int    `json:"criticalCount"`
	WarningCount  int    `json:"warningCount"`
	InfoCount     int    `json:"infoCount"`
}

// StatusResult is the result of a status command.
type StatusResult struct {
	NamespaceSummaries []NamespaceSummary `json:"namespaceSummaries"`
	TotalConstraints   int                `json:"totalConstraints"`
	TotalCritical      int                `json:"totalCritical"`
	TotalWarning       int                `json:"totalWarning"`
	TotalInfo          int                `json:"totalInfo"`
	NamespaceCount     int                `json:"namespaceCount"`
}

// getClientFunc is the function used to create a Kubernetes dynamic client.
// It can be overridden in tests to inject a fake client.
var getClientFunc = defaultGetClient

// getClient creates a Kubernetes dynamic client.
func getClient() (dynamic.Interface, error) {
	return getClientFunc()
}

func defaultGetClient() (dynamic.Interface, error) {
	// Use in-cluster config or kubeconfig
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, err
	}

	return dynamic.NewForConfig(config)
}

// outputResult outputs the result in the specified format.
func outputResult(result interface{}, format string) error {
	switch format {
	case "json":
		return outputJSON(result)
	case "yaml":
		return outputYAML(result)
	default:
		return outputTable(result)
	}
}

func outputJSON(result interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputYAML(result interface{}) error {
	data, err := yaml.Marshal(result)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputTable(result interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	switch r := result.(type) {
	case QueryResult:
		return outputQueryTable(w, r)
	case ExplainResult:
		return outputExplainTable(w, r)
	case CheckResult:
		return outputCheckTable(w, r)
	case RemediateResult:
		return outputRemediateTable(w, r)
	case StatusResult:
		return outputStatusTable(w, r)
	default:
		// Fall back to JSON for unknown types
		return outputJSON(result)
	}
}

func outputQueryTable(w *tabwriter.Writer, r QueryResult) error {
	fmt.Fprintf(w, "NAMESPACE\t%s\n", r.Namespace)
	fmt.Fprintf(w, "TOTAL\t%d\n\n", r.Total)

	fmt.Fprintln(w, "NAME\tTYPE\tSEVERITY\tEFFECT\tSOURCE")
	for _, c := range r.Constraints {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Type, c.Severity, c.Effect, c.Source)
	}

	return nil
}

func outputExplainTable(w *tabwriter.Writer, r ExplainResult) error {
	fmt.Fprintf(w, "ERROR:\t%s\n", r.ErrorMessage)
	fmt.Fprintf(w, "CONFIDENCE:\t%s\n", r.Confidence)
	fmt.Fprintf(w, "EXPLANATION:\t%s\n\n", r.Explanation)

	if len(r.MatchingConstraints) > 0 {
		fmt.Fprintln(w, "MATCHING CONSTRAINTS:")
		fmt.Fprintln(w, "NAME\tTYPE\tSEVERITY")
		for _, c := range r.MatchingConstraints {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.Type, c.Severity)
		}
	}

	if len(r.RemediationSteps) > 0 {
		fmt.Fprintln(w, "\nREMEDIATION STEPS:")
		for i, step := range r.RemediationSteps {
			fmt.Fprintf(w, "%d. [%s] %s\n", i+1, step.Type, step.Description)
			if step.Command != "" {
				fmt.Fprintf(w, "   Command: %s\n", step.Command)
			}
		}
	}

	return nil
}

func outputCheckTable(w *tabwriter.Writer, r CheckResult) error {
	status := "PASS"
	if r.WouldBlock {
		status = "BLOCKED"
	}

	fmt.Fprintf(w, "MANIFEST:\t%s/%s (%s)\n", r.Manifest.Namespace, r.Manifest.Name, r.Manifest.Kind)
	fmt.Fprintf(w, "STATUS:\t%s\n\n", status)

	if len(r.BlockingConstraints) > 0 {
		fmt.Fprintln(w, "BLOCKING CONSTRAINTS:")
		fmt.Fprintln(w, "NAME\tTYPE\tSEVERITY")
		for _, c := range r.BlockingConstraints {
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.Type, c.Severity)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "\nWARNINGS:")
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "- %s\n", warn)
		}
	}

	return nil
}

func outputRemediateTable(w *tabwriter.Writer, r RemediateResult) error {
	fmt.Fprintf(w, "CONSTRAINT:\t%s (%s)\n", r.Constraint.Name, r.Constraint.Type)
	fmt.Fprintf(w, "SEVERITY:\t%s\n", r.Constraint.Severity)
	fmt.Fprintf(w, "SUMMARY:\t%s\n\n", r.Summary)

	if len(r.Steps) > 0 {
		fmt.Fprintln(w, "REMEDIATION STEPS:")
		for i, step := range r.Steps {
			privilege := step.RequiresPrivilege
			if privilege == "" {
				privilege = "developer"
			}
			fmt.Fprintf(w, "\n%d. [%s] (%s)\n", i+1, step.Type, privilege)
			fmt.Fprintf(w, "   %s\n", step.Description)
			if step.Command != "" {
				fmt.Fprintf(w, "   $ %s\n", step.Command)
			}
		}
	}

	return nil
}

func outputStatusTable(w *tabwriter.Writer, r StatusResult) error {
	fmt.Fprintf(w, "TOTAL CONSTRAINTS:\t%d\n", r.TotalConstraints)
	fmt.Fprintf(w, "NAMESPACES:\t%d\n", r.NamespaceCount)
	fmt.Fprintf(w, "CRITICAL:\t%d\n", r.TotalCritical)
	fmt.Fprintf(w, "WARNING:\t%d\n", r.TotalWarning)
	fmt.Fprintf(w, "INFO:\t%d\n\n", r.TotalInfo)

	if len(r.NamespaceSummaries) > 0 {
		fmt.Fprintln(w, "NAMESPACE\tTOTAL\tCRITICAL\tWARNING\tINFO")
		for _, ns := range r.NamespaceSummaries {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\n",
				ns.Namespace, ns.Total, ns.CriticalCount, ns.WarningCount, ns.InfoCount)
		}
	}

	return nil
}

// severityColor returns ANSI color code for severity (used in table output).
func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "\033[31m" // Red
	case "warning":
		return "\033[33m" // Yellow
	case "info":
		return "\033[36m" // Cyan
	default:
		return ""
	}
}
