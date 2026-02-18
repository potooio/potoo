package util

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// SafeNestedString returns the string at the given field path, or "" if missing/wrong type.
func SafeNestedString(obj map[string]interface{}, fields ...string) string {
	if obj == nil {
		return ""
	}
	val, found, err := unstructured.NestedString(obj, fields...)
	if err != nil || !found {
		return ""
	}
	return val
}

// SafeNestedBool returns the bool at the given field path, or false if missing.
func SafeNestedBool(obj map[string]interface{}, fields ...string) bool {
	if obj == nil {
		return false
	}
	val, found, err := unstructured.NestedBool(obj, fields...)
	if err != nil || !found {
		return false
	}
	return val
}

// SafeNestedInt64 returns the int64 at the given field path, or 0 if missing.
func SafeNestedInt64(obj map[string]interface{}, fields ...string) int64 {
	if obj == nil {
		return 0
	}
	val, found, err := unstructured.NestedInt64(obj, fields...)
	if err != nil || !found {
		return 0
	}
	return val
}

// SafeNestedStringSlice returns the []string at the given field path, or nil if missing.
func SafeNestedStringSlice(obj map[string]interface{}, fields ...string) []string {
	if obj == nil {
		return nil
	}
	val, found, err := unstructured.NestedStringSlice(obj, fields...)
	if err != nil || !found {
		return nil
	}
	return val
}

// SafeNestedMap returns the nested map, or nil if missing.
func SafeNestedMap(obj map[string]interface{}, fields ...string) map[string]interface{} {
	if obj == nil {
		return nil
	}
	val, found, err := unstructured.NestedMap(obj, fields...)
	if err != nil || !found {
		return nil
	}
	return val
}

// SafeNestedSlice returns the nested slice, or nil if missing.
func SafeNestedSlice(obj map[string]interface{}, fields ...string) []interface{} {
	if obj == nil {
		return nil
	}
	val, found, err := unstructured.NestedSlice(obj, fields...)
	if err != nil || !found {
		return nil
	}
	return val
}

// SafeNestedLabelSelector parses a Kubernetes label selector from the given path.
//
// Expected structure at the path:
//
//	{
//	  "matchLabels": {"key": "value", ...},
//	  "matchExpressions": [
//	    {"key": "k", "operator": "In", "values": ["v1","v2"]},
//	  ]
//	}
//
// Returns nil if path doesn't exist. Returns non-nil (possibly empty) LabelSelector
// if the path exists (even as empty map — that means "select all").
func SafeNestedLabelSelector(obj map[string]interface{}, fields ...string) *metav1.LabelSelector {
	if obj == nil {
		return nil
	}

	selectorMap := SafeNestedMap(obj, fields...)
	if selectorMap == nil {
		return nil
	}

	selector := &metav1.LabelSelector{}

	// Extract matchLabels
	if matchLabelsRaw := SafeNestedMap(selectorMap, "matchLabels"); matchLabelsRaw != nil {
		matchLabels := make(map[string]string)
		for k, v := range matchLabelsRaw {
			if strVal, ok := v.(string); ok {
				matchLabels[k] = strVal
			}
		}
		selector.MatchLabels = matchLabels
	}

	// Extract matchExpressions
	if expressionsRaw := SafeNestedSlice(selectorMap, "matchExpressions"); expressionsRaw != nil {
		var expressions []metav1.LabelSelectorRequirement
		for _, exprRaw := range expressionsRaw {
			exprMap, ok := exprRaw.(map[string]interface{})
			if !ok {
				continue
			}

			req := metav1.LabelSelectorRequirement{
				Key:      SafeStringFromMap(exprMap, "key"),
				Operator: metav1.LabelSelectorOperator(SafeStringFromMap(exprMap, "operator")),
			}

			// Extract values
			if valuesRaw := SafeNestedSlice(exprMap, "values"); valuesRaw != nil {
				var values []string
				for _, v := range valuesRaw {
					if strVal, ok := v.(string); ok {
						values = append(values, strVal)
					}
				}
				req.Values = values
			}

			expressions = append(expressions, req)
		}
		selector.MatchExpressions = expressions
	}

	return selector
}

// SafeStringFromMap extracts a string value from a map by key.
// Returns "" if key is missing or value is not a string.
func SafeStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok {
		return ""
	}
	strVal, ok := val.(string)
	if !ok {
		return ""
	}
	return strVal
}
