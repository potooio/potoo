package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSafeNestedString(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"action": "deny",
			"nested": map[string]interface{}{
				"deep": "value",
			},
		},
	}

	assert.Equal(t, "deny", SafeNestedString(obj, "spec", "action"))
	assert.Equal(t, "value", SafeNestedString(obj, "spec", "nested", "deep"))
	assert.Equal(t, "", SafeNestedString(obj, "spec", "missing"))
	assert.Equal(t, "", SafeNestedString(obj, "nonexistent", "path"))
	assert.Equal(t, "", SafeNestedString(nil, "any"))
}

func TestSafeNestedBool(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"enabled":  true,
			"disabled": false,
		},
	}

	assert.Equal(t, true, SafeNestedBool(obj, "spec", "enabled"))
	assert.Equal(t, false, SafeNestedBool(obj, "spec", "disabled"))
	assert.Equal(t, false, SafeNestedBool(obj, "spec", "missing"))
	assert.Equal(t, false, SafeNestedBool(nil, "any"))
}

func TestSafeNestedInt64(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"replicas": int64(3),
		},
	}

	assert.Equal(t, int64(3), SafeNestedInt64(obj, "spec", "replicas"))
	assert.Equal(t, int64(0), SafeNestedInt64(obj, "spec", "missing"))
	assert.Equal(t, int64(0), SafeNestedInt64(nil, "any"))
}

func TestSafeNestedStringSlice(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"policyTypes": []interface{}{"Ingress", "Egress"},
		},
	}

	assert.Equal(t, []string{"Ingress", "Egress"}, SafeNestedStringSlice(obj, "spec", "policyTypes"))
	assert.Nil(t, SafeNestedStringSlice(obj, "spec", "missing"))
	assert.Nil(t, SafeNestedStringSlice(nil, "any"))
}

func TestSafeNestedMap(t *testing.T) {
	obj := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{
				"app": "test",
			},
		},
	}

	result := SafeNestedMap(obj, "metadata", "labels")
	require.NotNil(t, result)
	assert.Equal(t, "test", result["app"])
	assert.Nil(t, SafeNestedMap(obj, "metadata", "missing"))
	assert.Nil(t, SafeNestedMap(nil, "any"))
}

func TestSafeNestedSlice(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{"name": "rule1"},
				map[string]interface{}{"name": "rule2"},
			},
		},
	}

	result := SafeNestedSlice(obj, "spec", "rules")
	require.NotNil(t, result)
	assert.Len(t, result, 2)
	assert.Nil(t, SafeNestedSlice(obj, "spec", "missing"))
	assert.Nil(t, SafeNestedSlice(nil, "any"))
}

func TestSafeNestedLabelSelector_MatchLabels(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app":  "web",
					"tier": "frontend",
				},
			},
		},
	}

	sel := SafeNestedLabelSelector(obj, "spec", "podSelector")
	require.NotNil(t, sel)
	assert.Equal(t, map[string]string{"app": "web", "tier": "frontend"}, sel.MatchLabels)
}

func TestSafeNestedLabelSelector_Empty(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{},
		},
	}

	// Empty selector (selects all) should return a non-nil LabelSelector with no matchLabels
	sel := SafeNestedLabelSelector(obj, "spec", "podSelector")
	// An empty map IS a valid selector (matches everything), so return non-nil
	require.NotNil(t, sel)
}

func TestSafeNestedLabelSelector_Missing(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{},
	}

	sel := SafeNestedLabelSelector(obj, "spec", "podSelector")
	assert.Nil(t, sel)
}

func TestSafeNestedLabelSelector_Nil(t *testing.T) {
	assert.Nil(t, SafeNestedLabelSelector(nil, "spec", "podSelector"))
}

func TestSafeNestedLabelSelector_MatchExpressions(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"app": "web",
				},
				"matchExpressions": []interface{}{
					map[string]interface{}{
						"key":      "env",
						"operator": "In",
						"values":   []interface{}{"prod", "staging"},
					},
				},
			},
		},
	}

	sel := SafeNestedLabelSelector(obj, "spec", "selector")
	require.NotNil(t, sel)
	assert.Equal(t, "web", sel.MatchLabels["app"])
	require.Len(t, sel.MatchExpressions, 1)
	assert.Equal(t, "env", sel.MatchExpressions[0].Key)
	assert.Equal(t, metav1.LabelSelectorOpIn, sel.MatchExpressions[0].Operator)
	assert.Equal(t, []string{"prod", "staging"}, sel.MatchExpressions[0].Values)
}

func TestSafeStringFromMap(t *testing.T) {
	m := map[string]interface{}{
		"name":  "test",
		"count": 42,
	}

	assert.Equal(t, "test", SafeStringFromMap(m, "name"))
	assert.Equal(t, "", SafeStringFromMap(m, "count")) // not a string
	assert.Equal(t, "", SafeStringFromMap(m, "missing"))
	assert.Equal(t, "", SafeStringFromMap(nil, "any"))
}
