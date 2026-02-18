// potooctl is a CLI tool for querying Potoo constraint data.
//
// Installation:
//
//	go build -o potoo ./cmd/potooctl
//	mv potoo /usr/local/bin/
//
// Usage:
//
//	potoo query -n my-namespace
//	potoo explain -n my-namespace "connection refused"
//	potoo check -f manifest.yaml
//	potoo remediate -n my-namespace my-constraint
//	potoo status
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	outputFmt string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "potoo",
		Short: "Query and explain Potoo constraints",
		Long: `potoo is a CLI tool for interacting with Potoo.

It reads ConstraintReport CRDs and Events directly from the cluster,
providing structured JSON output that matches MCP response schemas.`,
		Version: version,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json, yaml")

	// Add subcommands
	rootCmd.AddCommand(queryCmd())
	rootCmd.AddCommand(explainCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(remediateCmd())
	rootCmd.AddCommand(statusCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
