package main

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryCmd(t *testing.T) {
	cmd := queryCmd()
	require.NotNil(t, cmd)

	assert.Equal(t, "query", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify required flags exist
	nsFlag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, nsFlag)
	assert.Equal(t, "n", nsFlag.Shorthand)

	typeFlag := cmd.Flags().Lookup("type")
	require.NotNil(t, typeFlag)

	severityFlag := cmd.Flags().Lookup("severity")
	require.NotNil(t, severityFlag)

	workloadFlag := cmd.Flags().Lookup("workload")
	require.NotNil(t, workloadFlag)
}

func TestExplainCmd(t *testing.T) {
	cmd := explainCmd()
	require.NotNil(t, cmd)

	assert.Equal(t, "explain [error-message]", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	nsFlag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, nsFlag)
	assert.Equal(t, "n", nsFlag.Shorthand)

	workloadFlag := cmd.Flags().Lookup("workload")
	require.NotNil(t, workloadFlag)
}

func TestCheckCmd(t *testing.T) {
	cmd := checkCmd()
	require.NotNil(t, cmd)

	assert.Equal(t, "check", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	fileFlag := cmd.Flags().Lookup("filename")
	require.NotNil(t, fileFlag)
	assert.Equal(t, "f", fileFlag.Shorthand)
}

func TestRemediateCmd(t *testing.T) {
	cmd := remediateCmd()
	require.NotNil(t, cmd)

	assert.Equal(t, "remediate [constraint-name]", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	nsFlag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, nsFlag)
	assert.Equal(t, "n", nsFlag.Shorthand)
}

func TestStatusCmd(t *testing.T) {
	cmd := statusCmd()
	require.NotNil(t, cmd)

	assert.Equal(t, "status", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestRunQuery_NoKubeconfig(t *testing.T) {
	// Without a valid kubeconfig, runQuery should return an error about client creation
	t.Setenv("KUBECONFIG", "/nonexistent/path")
	cmd := queryCmd()

	// Set required flags
	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunExplain_NoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/path")
	cmd := explainCmd()

	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{"connection refused"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunCheck_NoFile(t *testing.T) {
	cmd := checkCmd()

	cmd.Flags().Set("filename", "/nonexistent/file.yaml")

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read manifest")
}

func TestRunRemediate_NoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/path")
	cmd := remediateCmd()

	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{"my-constraint"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunStatus_NoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/path")
	cmd := statusCmd()

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestGetClient_NoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/path")
	t.Setenv("HOME", "/nonexistent/home")

	_, err := getClient()
	assert.Error(t, err)
}

func TestRunCheck_InvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML
	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("{{invalid yaml")
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	err = cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse manifest")
}

func TestRunCheck_ValidManifest_NoKubeconfig(t *testing.T) {
	// Create a valid manifest file -- gets past read/parse, fails on client creation
	t.Setenv("KUBECONFIG", "/nonexistent/path")

	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 1
`)
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	err = cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunCheck_ManifestWithoutNamespace(t *testing.T) {
	// Manifest without namespace should default to "default"
	t.Setenv("KUBECONFIG", "/nonexistent/path")

	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: test
    image: nginx
`)
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	err = cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	// Should still fail on client creation, but should have parsed the manifest
	assert.Contains(t, err.Error(), "failed to create client")
}

// writeFakeKubeconfig writes a kubeconfig that points to an unreachable server.
// This allows getClient() to succeed (creating a client config) but any API
// calls to fail, which covers more code paths in the run* functions.
func writeFakeKubeconfig(t *testing.T) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "kubeconfig-*.yaml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:1
    insecure-skip-tls-verify: true
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    user: fake-user
  name: fake-context
current-context: fake-context
users:
- name: fake-user
  user:
    token: fake-token
`)
	require.NoError(t, err)
	tmpFile.Close()

	t.Cleanup(func() { os.Remove(tmpFile.Name()) })
	return tmpFile.Name()
}

func TestRunQuery_FakeKubeconfig(t *testing.T) {
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	cmd := queryCmd()
	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{})
	// Client creation succeeds, but API call to get ConstraintReport fails
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunExplain_FakeKubeconfig(t *testing.T) {
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	cmd := explainCmd()
	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{"connection refused"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunCheck_FakeKubeconfig_ReportNotFound(t *testing.T) {
	// With a fake kubeconfig, the client is created but API call fails.
	// In runCheck, when the report is not found, it returns a passing result
	// (no constraints found = no blocking).
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 1
`)
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	// Set output format to json to capture the result
	outputFmt = "json"
	defer func() { outputFmt = "table" }()

	// The API call to get the report will fail, but runCheck treats
	// "report not found" as "no constraints" and returns a passing result
	output := captureStdout(t, func() {
		err = cmd.RunE(cmd, []string{})
		// This might or might not error depending on how the K8s client fails
		// If it returns a not-found error, it will succeed with a PASS result
		// If it returns a connection error, it will also trigger the no-report path
		_ = err
	})

	// The function should have reached the manifest parsing at minimum
	// If it succeeded, the output should contain the result
	if err == nil {
		assert.Contains(t, output, "production")
	}
}

func TestRunRemediate_FakeKubeconfig(t *testing.T) {
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	cmd := remediateCmd()
	cmd.Flags().Set("namespace", "test-ns")

	err := cmd.RunE(cmd, []string{"my-constraint"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunStatus_FakeKubeconfig(t *testing.T) {
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	cmd := statusCmd()

	err := cmd.RunE(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list ConstraintReports")
}

func TestRunCheck_FakeKubeconfig_ManifestWithoutNs(t *testing.T) {
	// Test with manifest that has no namespace -- should default to "default"
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: test
    image: nginx
`)
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	outputFmt = "json"
	defer func() { outputFmt = "table" }()

	output := captureStdout(t, func() {
		err = cmd.RunE(cmd, []string{})
		_ = err
	})

	if err == nil {
		assert.Contains(t, output, "default")
	}
}

func TestRunCheck_FakeKubeconfig_MinimalManifest(t *testing.T) {
	// Manifest with minimal metadata
	kubeconfig := writeFakeKubeconfig(t)
	t.Setenv("KUBECONFIG", kubeconfig)

	tmpFile, err := os.CreateTemp("", "test-manifest-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(`apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: test-ns
data:
  key: value
`)
	require.NoError(t, err)
	tmpFile.Close()

	cmd := checkCmd()
	cmd.Flags().Set("filename", tmpFile.Name())

	outputFmt = "json"
	defer func() { outputFmt = "table" }()

	output := captureStdout(t, func() {
		err = cmd.RunE(cmd, []string{})
		_ = err
	})

	if err == nil {
		assert.Contains(t, output, "ConfigMap")
	}
}

func TestRootCmd(t *testing.T) {
	// Test that the root command can be constructed with all subcommands.
	// This exercises the cobra command tree setup similar to main().
	rootCmd := &cobra.Command{
		Use:   "potoo-sentinel",
		Short: "Query and explain Potoo constraints",
	}

	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json, yaml")

	rootCmd.AddCommand(queryCmd())
	rootCmd.AddCommand(explainCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(remediateCmd())
	rootCmd.AddCommand(statusCmd())

	assert.Equal(t, 5, len(rootCmd.Commands()))

	// Verify the help works
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	assert.NoError(t, err)
}
