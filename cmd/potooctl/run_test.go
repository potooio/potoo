package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

var constraintReportGVR = schema.GroupVersionResource{
	Group:    "potoo.io",
	Version:  "v1alpha1",
	Resource: "constraintreports",
}

// makeFakeClient creates a fake dynamic client and pre-populates it with the
// given unstructured objects via the client API so that namespace + GVR
// routing works correctly.
func makeFakeClient(objects ...*unstructured.Unstructured) dynamic.Interface {
	s := runtime.NewScheme()
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "potoo.io", Version: "v1alpha1", Kind: "ConstraintReport"},
		&unstructured.Unstructured{},
	)
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "potoo.io", Version: "v1alpha1", Kind: "ConstraintReportList"},
		&unstructured.UnstructuredList{},
	)

	gvrToListKind := map[schema.GroupVersionResource]string{
		constraintReportGVR: "ConstraintReportList",
	}

	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(s, gvrToListKind)

	ctx := context.Background()
	for _, obj := range objects {
		ns := obj.GetNamespace()
		client.Resource(constraintReportGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	}

	return client
}

// setFakeClient installs a fake dynamic client for the duration of the test
// and restores the original getClientFunc on cleanup.
func setFakeClient(t *testing.T, client dynamic.Interface) {
	t.Helper()
	orig := getClientFunc
	getClientFunc = func() (dynamic.Interface, error) {
		return client, nil
	}
	t.Cleanup(func() { getClientFunc = orig })
}

// makeConstraintReport builds an unstructured ConstraintReport with the given
// namespace and constraints in the machineReadable section.
func makeConstraintReport(namespace string, constraints []map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "potoo.io/v1alpha1",
			"kind":       "ConstraintReport",
			"metadata": map[string]interface{}{
				"name":      "constraints",
				"namespace": namespace,
			},
			"status": map[string]interface{}{
				"constraintCount": int64(len(constraints)),
				"criticalCount":   int64(0),
				"warningCount":    int64(0),
				"infoCount":       int64(0),
				"machineReadable": map[string]interface{}{
					"constraints": toSlice(constraints),
				},
			},
		},
	}
	var crit, warn, info int64
	for _, c := range constraints {
		switch c["severity"] {
		case "Critical":
			crit++
		case "Warning":
			warn++
		case "Info":
			info++
		}
	}
	unstructured.SetNestedField(obj.Object, crit, "status", "criticalCount")
	unstructured.SetNestedField(obj.Object, warn, "status", "warningCount")
	unstructured.SetNestedField(obj.Object, info, "status", "infoCount")
	return obj
}

func toSlice(maps []map[string]interface{}) []interface{} {
	result := make([]interface{}, len(maps))
	for i, m := range maps {
		result[i] = m
	}
	return result
}

// ---------------------------------------------------------------------------
// runQuery success path
// ---------------------------------------------------------------------------

func TestRunQuery_Success(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
		{"name": "limit-cpu", "type": "ResourceLimit", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := queryCmd()
	queryNamespace = "test-ns"
	queryConstraintType = ""
	querySeverity = ""
	queryWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runQuery(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "deny-egress")
	assert.Contains(t, output, "limit-cpu")
	assert.Contains(t, output, "test-ns")
}

func TestRunQuery_WithTypeFilter(t *testing.T) {
	report := makeConstraintReport("prod", []map[string]interface{}{
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
		{"name": "admission-check", "type": "Admission", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := queryCmd()
	queryNamespace = "prod"
	queryConstraintType = "NetworkEgress"
	querySeverity = ""
	queryWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runQuery(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "deny-egress")
	assert.NotContains(t, output, "admission-check")
}

// ---------------------------------------------------------------------------
// runExplain success path
// ---------------------------------------------------------------------------

func TestRunExplain_Success_NetworkError(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
		{"name": "require-labels", "type": "Admission", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"connection refused"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "deny-egress")
	assert.Contains(t, output, "high")
	assert.Contains(t, output, "network")
}

func TestRunExplain_Success_WithRemediation(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{
			"name":     "deny-egress",
			"type":     "NetworkEgress",
			"severity": "Critical",
			"remediation": map[string]interface{}{
				"summary": "Allow egress",
				"steps": []interface{}{
					map[string]interface{}{
						"type":        "command",
						"description": "Apply policy",
						"command":     "kubectl apply -f np.yaml",
					},
				},
			},
		},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"connection refused"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "kubectl apply -f np.yaml")
	assert.Contains(t, output, "remediationSteps")
}

// ---------------------------------------------------------------------------
// runCheck success path
// ---------------------------------------------------------------------------

func TestRunCheck_Success_NoBlocking(t *testing.T) {
	report := makeConstraintReport("prod", []map[string]interface{}{
		{"name": "limit-cpu", "type": "ResourceLimit", "severity": "Warning", "message": "CPU close to limit"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := checkCmd()
	tmpDir := t.TempDir()
	checkFile = tmpDir + "/deploy.yaml"
	require.NoError(t, writeManifest(checkFile, "prod", "web-app", "Deployment"))
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runCheck(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "\"wouldBlock\": false")
	assert.Contains(t, output, "web-app")
}

func TestRunCheck_Success_Blocking(t *testing.T) {
	report := makeConstraintReport("prod", []map[string]interface{}{
		{"name": "require-labels", "type": "Admission", "severity": "Critical", "message": "Missing required labels"},
		{"name": "limit-cpu", "type": "ResourceLimit", "severity": "Warning", "message": "CPU close to limit"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := checkCmd()
	tmpDir := t.TempDir()
	checkFile = tmpDir + "/deploy.yaml"
	require.NoError(t, writeManifest(checkFile, "prod", "web-app", "Deployment"))
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runCheck(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "\"wouldBlock\": true")
	assert.Contains(t, output, "require-labels")
}

func TestRunCheck_NoReport(t *testing.T) {
	setFakeClient(t, makeFakeClient())

	cmd := checkCmd()
	tmpDir := t.TempDir()
	checkFile = tmpDir + "/deploy.yaml"
	require.NoError(t, writeManifest(checkFile, "staging", "api", "Deployment"))
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runCheck(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "\"wouldBlock\": false")
}

// ---------------------------------------------------------------------------
// runRemediate success path
// ---------------------------------------------------------------------------

func TestRunRemediate_Success_WithRemediation(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{
			"name":     "deny-egress",
			"type":     "NetworkEgress",
			"severity": "Critical",
			"remediation": map[string]interface{}{
				"summary": "Allow egress traffic",
				"steps": []interface{}{
					map[string]interface{}{
						"type":              "command",
						"description":       "Apply network policy",
						"command":           "kubectl apply -f allow-egress.yaml",
						"requiresPrivilege": "admin",
					},
				},
			},
		},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := remediateCmd()
	remediateNamespace = "test-ns"
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runRemediate(cmd, []string{"deny-egress"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Allow egress traffic")
	assert.Contains(t, output, "kubectl apply -f allow-egress.yaml")
	assert.Contains(t, output, "admin")
}

func TestRunRemediate_Success_NoRemediation(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "my-constraint", "type": "Admission", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := remediateCmd()
	remediateNamespace = "test-ns"
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runRemediate(cmd, []string{"my-constraint"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Contact your platform team")
	assert.Contains(t, output, "manual")
}

func TestRunRemediate_ConstraintNotFound(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "other-constraint", "type": "Admission", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := remediateCmd()
	remediateNamespace = "test-ns"

	err := runRemediate(cmd, []string{"nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// runStatus success path
// ---------------------------------------------------------------------------

func TestRunStatus_Success(t *testing.T) {
	report1 := makeConstraintReport("prod", []map[string]interface{}{
		{"name": "c1", "type": "NetworkEgress", "severity": "Critical"},
		{"name": "c2", "type": "Admission", "severity": "Warning"},
	})
	report2 := makeConstraintReport("dev", []map[string]interface{}{
		{"name": "c3", "type": "ResourceLimit", "severity": "Info"},
	})
	setFakeClient(t, makeFakeClient(report1, report2))

	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runStatus(statusCmd(), nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "namespaceSummaries")
	assert.Contains(t, output, "totalConstraints")
}

func TestRunStatus_Empty(t *testing.T) {
	setFakeClient(t, makeFakeClient())

	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runStatus(statusCmd(), nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "\"totalConstraints\": 0")
	assert.Contains(t, output, "\"namespaceCount\": 0")
}

// ---------------------------------------------------------------------------
// Table output for run* commands
// ---------------------------------------------------------------------------

func TestRunQuery_TableOutput(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := queryCmd()
	queryNamespace = "test-ns"
	queryConstraintType = ""
	querySeverity = ""
	queryWorkload = ""
	outputFmt = "table"

	output := captureStdout(t, func() {
		err := runQuery(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "NAMESPACE")
	assert.Contains(t, output, "deny-egress")
}

func TestRunExplain_TableOutput(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "table"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"connection refused"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "ERROR:")
	assert.Contains(t, output, "deny-egress")
}

// ---------------------------------------------------------------------------
// matchError coverage: admission, quota, and no-match paths
// ---------------------------------------------------------------------------

func TestRunExplain_AdmissionError(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "require-labels", "type": "Admission", "severity": "Critical"},
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Warning"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"denied by policy"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "require-labels")
	assert.Contains(t, output, "high")
	assert.Contains(t, output, "admission")
}

func TestRunExplain_QuotaError(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "cpu-limit", "type": "ResourceLimit", "severity": "Warning"},
		{"name": "deny-egress", "type": "NetworkEgress", "severity": "Critical"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"exceeded quota for cpu"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "cpu-limit")
	assert.Contains(t, output, "high")
	assert.Contains(t, output, "quota")
}

func TestRunExplain_NoMatchError(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "some-constraint", "type": "Custom", "severity": "Info"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := explainCmd()
	explainNamespace = "test-ns"
	explainWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runExplain(cmd, []string{"some random error"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "low")
	assert.Contains(t, output, "some-constraint")
}

// ---------------------------------------------------------------------------
// Additional run* path coverage
// ---------------------------------------------------------------------------

func TestRunQuery_SeverityFilter(t *testing.T) {
	report := makeConstraintReport("test-ns", []map[string]interface{}{
		{"name": "crit1", "type": "NetworkEgress", "severity": "Critical"},
		{"name": "warn1", "type": "Admission", "severity": "Warning"},
		{"name": "info1", "type": "Custom", "severity": "Info"},
	})
	setFakeClient(t, makeFakeClient(report))

	cmd := queryCmd()
	queryNamespace = "test-ns"
	queryConstraintType = ""
	querySeverity = "Warning"
	queryWorkload = ""
	outputFmt = "json"

	output := captureStdout(t, func() {
		err := runQuery(cmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "warn1")
	assert.NotContains(t, output, "crit1")
	assert.NotContains(t, output, "info1")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeManifest(path, namespace, name, kind string) error {
	content := "apiVersion: apps/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n"
	if namespace != "" {
		content += "  namespace: " + namespace + "\n"
	}
	return os.WriteFile(path, []byte(content), 0644)
}
