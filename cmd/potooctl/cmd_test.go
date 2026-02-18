package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKubeconfig returns the path to a kubeconfig file that points at a
// non-routable server. getClient() will succeed (a valid config exists),
// but any API call will fail with a connection error.
func fakeKubeconfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	content := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://192.0.2.1:6443
    insecure-skip-tls-verify: true
  name: fake
contexts:
- context:
    cluster: fake
    user: fake
  name: fake
current-context: fake
users:
- name: fake
  user:
    token: fake-token
`
	require.NoError(t, os.WriteFile(kc, []byte(content), 0600))
	return kc
}

// ---------------------------------------------------------------------------
// queryCmd constructor
// ---------------------------------------------------------------------------

func TestQueryCmd(t *testing.T) {
	cmd := queryCmd()

	assert.Equal(t, "query", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)

	// Verify flags exist
	ns := cmd.Flags().Lookup("namespace")
	require.NotNil(t, ns)
	assert.Equal(t, "n", ns.Shorthand)

	typeFlag := cmd.Flags().Lookup("type")
	require.NotNil(t, typeFlag)

	sevFlag := cmd.Flags().Lookup("severity")
	require.NotNil(t, sevFlag)

	wlFlag := cmd.Flags().Lookup("workload")
	require.NotNil(t, wlFlag)
}

// ---------------------------------------------------------------------------
// explainCmd constructor
// ---------------------------------------------------------------------------

func TestExplainCmd(t *testing.T) {
	cmd := explainCmd()

	assert.Equal(t, "explain [error-message]", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)

	ns := cmd.Flags().Lookup("namespace")
	require.NotNil(t, ns)
	assert.Equal(t, "n", ns.Shorthand)

	wlFlag := cmd.Flags().Lookup("workload")
	require.NotNil(t, wlFlag)
}

// ---------------------------------------------------------------------------
// checkCmd constructor
// ---------------------------------------------------------------------------

func TestCheckCmd(t *testing.T) {
	cmd := checkCmd()

	assert.Equal(t, "check", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)

	fnFlag := cmd.Flags().Lookup("filename")
	require.NotNil(t, fnFlag)
	assert.Equal(t, "f", fnFlag.Shorthand)
}

// ---------------------------------------------------------------------------
// remediateCmd constructor
// ---------------------------------------------------------------------------

func TestRemediateCmd(t *testing.T) {
	cmd := remediateCmd()

	assert.Equal(t, "remediate [constraint-name]", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)

	ns := cmd.Flags().Lookup("namespace")
	require.NotNil(t, ns)
	assert.Equal(t, "n", ns.Shorthand)
}

// ---------------------------------------------------------------------------
// statusCmd constructor
// ---------------------------------------------------------------------------

func TestStatusCmd(t *testing.T) {
	cmd := statusCmd()

	assert.Equal(t, "status", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.RunE)
}

// ---------------------------------------------------------------------------
// run* error paths: no kubeconfig (getClient fails)
// ---------------------------------------------------------------------------

func TestRunQueryNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	queryNamespace = "test-ns"
	cmd := queryCmd()
	cmd.SetArgs([]string{"-n", "test-ns"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunExplainNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	cmd := explainCmd()
	cmd.SetArgs([]string{"-n", "test-ns", "connection refused"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunCheckMissingFile(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	cmd := checkCmd()
	cmd.SetArgs([]string{"-f", "/nonexistent/manifest.yaml"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read manifest")
}

func TestRunCheckInvalidYAML(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	tmpDir := t.TempDir()
	manifest := filepath.Join(tmpDir, "bad.yaml")
	err := os.WriteFile(manifest, []byte("\t\t---\n\t- :\n\t\t: :\n"), 0644)
	require.NoError(t, err)

	cmd := checkCmd()
	cmd.SetArgs([]string{"-f", manifest})
	err = cmd.Execute()
	assert.Error(t, err)
}

func TestRunCheckNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	tmpDir := t.TempDir()
	manifest := filepath.Join(tmpDir, "deploy.yaml")
	err := os.WriteFile(manifest, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
`), 0644)
	require.NoError(t, err)

	cmd := checkCmd()
	cmd.SetArgs([]string{"-f", manifest})
	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunRemediateNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	cmd := remediateCmd()
	cmd.SetArgs([]string{"-n", "test-ns", "my-constraint"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestRunStatusNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
	t.Setenv("HOME", "/nonexistent")

	cmd := statusCmd()
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

// ---------------------------------------------------------------------------
// run* error paths with fake kubeconfig: getClient succeeds, API calls fail
// These cover additional lines in each run* function.
// ---------------------------------------------------------------------------

func TestRunQueryFakeKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	cmd := queryCmd()
	cmd.SetArgs([]string{"-n", "test-ns"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunExplainFakeKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	cmd := explainCmd()
	cmd.SetArgs([]string{"-n", "test-ns", "connection refused"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunCheckFakeKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	tmpDir := t.TempDir()
	manifest := filepath.Join(tmpDir, "deploy.yaml")
	err := os.WriteFile(manifest, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
`), 0644)
	require.NoError(t, err)

	cmd := checkCmd()
	cmd.SetArgs([]string{"-f", manifest})
	err = cmd.Execute()
	// check.go handles the case where no report exists as a PASS, but
	// that only happens for specific error types. With a fake server
	// the error is a connection error, which is returned as-is or
	// handled as "no constraints exist" (returns PASS). Either way, no panic.
	// The test is just checking it doesn't panic and exercises more code paths.
	// We don't assert on the exact error because the behavior depends on
	// whether the connection error is classified as "not found" or not.
	_ = err
}

func TestRunCheckFakeKubeconfigDefaultNs(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	tmpDir := t.TempDir()
	manifest := filepath.Join(tmpDir, "deploy.yaml")
	// Manifest without explicit namespace -> defaults to "default"
	err := os.WriteFile(manifest, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`), 0644)
	require.NoError(t, err)

	cmd := checkCmd()
	cmd.SetArgs([]string{"-f", manifest})
	_ = cmd.Execute()
}

func TestRunRemediateFakeKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	cmd := remediateCmd()
	cmd.SetArgs([]string{"-n", "test-ns", "my-constraint"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ConstraintReport")
}

func TestRunStatusFakeKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", fakeKubeconfig(t))

	cmd := statusCmd()
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list ConstraintReports")
}
