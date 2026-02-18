package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/potooio/potoo/internal/types"
)

// mockQuerier is a test double for ConstraintQuerier.
type mockQuerier struct {
	constraints []types.Constraint
	err         error
}

func (m *mockQuerier) Query(ctx context.Context, namespace string, labels map[string]string) ([]types.Constraint, error) {
	return m.constraints, m.err
}

// buildAdmissionReview creates a valid AdmissionReview JSON body for testing.
func buildAdmissionReview(namespace, name string, labels map[string]string) []byte {
	obj := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
			"labels":    labels,
		},
	}
	objBytes, _ := json.Marshal(obj)

	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Namespace: namespace,
			Name:      name,
			Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: objBytes},
		},
	}
	body, _ := json.Marshal(review)
	return body
}

// decodeAdmissionReview parses an AdmissionReview from a response body.
func decodeAdmissionReview(t *testing.T, body []byte) admissionv1.AdmissionReview {
	t.Helper()
	var review admissionv1.AdmissionReview
	err := json.Unmarshal(body, &review)
	require.NoError(t, err, "failed to decode AdmissionReview response")
	return review
}

func TestNewAdmissionHandler(t *testing.T) {
	querier := &mockQuerier{}
	logger := zap.NewNop()

	handler := NewAdmissionHandler(querier, logger)

	require.NotNil(t, handler)
	assert.NotNil(t, handler.client)
	assert.NotNil(t, handler.logger)
}

func TestHandle_MethodNotAllowed(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandle_WrongContentType(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	body := buildAdmissionReview("default", "my-app", nil)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
}

func TestHandle_ValidRequest_NoConstraints(t *testing.T) {
	querier := &mockQuerier{
		constraints: nil,
		err:         nil,
	}
	handler := NewAdmissionHandler(querier, zap.NewNop())

	body := buildAdmissionReview("default", "my-app", map[string]string{"app": "web"})
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	review := decodeAdmissionReview(t, w.Body.Bytes())
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "response must always be allowed")
	assert.Empty(t, review.Response.Warnings)
}

func TestHandle_ValidRequest_WithWarnings(t *testing.T) {
	querier := &mockQuerier{
		constraints: []types.Constraint{
			{
				Name:            "deny-egress",
				Severity:        types.SeverityWarning,
				Summary:         "Egress restricted to port 443",
				RemediationHint: "Add egress exception label",
			},
			{
				Name:            "require-labels",
				Severity:        types.SeverityCritical,
				Summary:         "Missing required labels",
				RemediationHint: "Add team and cost-center labels",
			},
		},
		err: nil,
	}
	handler := NewAdmissionHandler(querier, zap.NewNop())

	body := buildAdmissionReview("team-alpha", "my-deploy", map[string]string{"app": "web"})
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	review := decodeAdmissionReview(t, w.Body.Bytes())
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "response must always be allowed even with warnings")
	assert.Len(t, review.Response.Warnings, 2)
	assert.Contains(t, review.Response.Warnings[0], "Egress restricted to port 443")
	assert.Contains(t, review.Response.Warnings[1], "Missing required labels")
}

func TestHandle_InvalidBody(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	// Fail-open: should still return 200 with allowed=true
	assert.Equal(t, http.StatusOK, w.Code)

	review := decodeAdmissionReview(t, w.Body.Bytes())
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "invalid body must still be allowed (fail-open)")
}

func TestExtractLabels(t *testing.T) {
	t.Run("valid labels", func(t *testing.T) {
		obj := map[string]interface{}{
			"metadata": map[string]interface{}{
				"labels": map[string]string{
					"app":  "web",
					"team": "alpha",
				},
			},
		}
		objBytes, _ := json.Marshal(obj)

		req := &admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Raw: objBytes},
		}

		labels := extractLabels(req)
		require.NotNil(t, labels)
		assert.Equal(t, "web", labels["app"])
		assert.Equal(t, "alpha", labels["team"])
	})

	t.Run("nil raw object", func(t *testing.T) {
		req := &admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Raw: nil},
		}

		labels := extractLabels(req)
		assert.Nil(t, labels)
	})

	t.Run("object without labels", func(t *testing.T) {
		obj := map[string]interface{}{
			"metadata": map[string]interface{}{
				"name": "no-labels",
			},
		}
		objBytes, _ := json.Marshal(obj)

		req := &admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Raw: objBytes},
		}

		labels := extractLabels(req)
		assert.Nil(t, labels)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := &admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Raw: []byte("{invalid")},
		}

		labels := extractLabels(req)
		assert.Nil(t, labels)
	})
}

func TestBuildWarnings(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	req := &admissionv1.AdmissionRequest{
		Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
	}

	constraints := []types.Constraint{
		{
			Name:            "warning-constraint",
			Severity:        types.SeverityWarning,
			Summary:         "Warning level issue",
			RemediationHint: "Fix warning",
		},
		{
			Name:            "critical-constraint",
			Severity:        types.SeverityCritical,
			Summary:         "Critical level issue",
			RemediationHint: "Fix critical",
		},
		{
			Name:            "info-constraint",
			Severity:        types.SeverityInfo,
			Summary:         "Info level issue",
			RemediationHint: "Just FYI",
		},
	}

	warnings := handler.buildWarnings(req, constraints)

	// Info severity should be filtered out; only Warning and Critical remain
	assert.Len(t, warnings, 2)
	assert.Contains(t, warnings[0], "Warning level issue")
	assert.Contains(t, warnings[1], "Critical level issue")

	t.Run("filters by resource target", func(t *testing.T) {
		constraintsWithTargets := []types.Constraint{
			{
				Name:            "matches-deployment",
				Severity:        types.SeverityWarning,
				Summary:         "Applies to deployments",
				RemediationHint: "Fix it",
				ResourceTargets: []types.ResourceTarget{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
				},
			},
			{
				Name:            "matches-pods-only",
				Severity:        types.SeverityWarning,
				Summary:         "Only applies to pods",
				RemediationHint: "Fix it",
				ResourceTargets: []types.ResourceTarget{
					{APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			},
		}

		warnings := handler.buildWarnings(req, constraintsWithTargets)
		assert.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "Applies to deployments")
	})
}

func TestConstraintApplies(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	req := &admissionv1.AdmissionRequest{
		Kind: metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
	}

	t.Run("no targets means applies to all", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: nil,
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("matching target", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
			},
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("non-matching target", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		}
		assert.False(t, handler.constraintApplies(req, c))
	})

	t.Run("wildcard resource", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{"apps"}, Resources: []string{"*"}},
			},
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("wildcard API group", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{"*"}, Resources: []string{"deployments"}},
			},
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("non-matching API group", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{"batch"}, Resources: []string{"deployments"}},
			},
		}
		assert.False(t, handler.constraintApplies(req, c))
	})

	t.Run("empty API groups means any group matches", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{}, Resources: []string{"deployments"}},
			},
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("multiple targets one matches", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{""}, Resources: []string{"pods"}},
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
			},
		}
		assert.True(t, handler.constraintApplies(req, c))
	})

	t.Run("multiple targets none match", func(t *testing.T) {
		c := types.Constraint{
			ResourceTargets: []types.ResourceTarget{
				{APIGroups: []string{""}, Resources: []string{"pods"}},
				{APIGroups: []string{"batch"}, Resources: []string{"jobs"}},
			},
		}
		assert.False(t, handler.constraintApplies(req, c))
	})
}

func TestFormatWarning(t *testing.T) {
	handler := NewAdmissionHandler(&mockQuerier{}, zap.NewNop())

	t.Run("warning severity", func(t *testing.T) {
		c := types.Constraint{
			Severity:        types.SeverityWarning,
			Summary:         "Egress restricted",
			RemediationHint: "Add exception label",
		}

		result := handler.formatWarning(c)
		assert.Equal(t, "[WARNING] Egress restricted - Add exception label", result)
	})

	t.Run("critical severity", func(t *testing.T) {
		c := types.Constraint{
			Severity:        types.SeverityCritical,
			Summary:         "Missing required labels",
			RemediationHint: "Contact platform-team@company.com",
		}

		result := handler.formatWarning(c)
		assert.Equal(t, "[CRITICAL] Missing required labels - Contact platform-team@company.com", result)
	})
}

func TestHandle_FailOpen_OnQueryError(t *testing.T) {
	querier := &mockQuerier{
		constraints: nil,
		err:         errors.New("connection refused"),
	}
	handler := NewAdmissionHandler(querier, zap.NewNop())

	body := buildAdmissionReview("default", "my-app", map[string]string{"app": "web"})
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Handle(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	review := decodeAdmissionReview(t, w.Body.Bytes())
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "query error must still be allowed (fail-open)")
	assert.Empty(t, review.Response.Warnings, "no warnings should be returned on query error")
}
