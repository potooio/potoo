package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetInt64(t *testing.T) {
	tests := []struct {
		name      string
		obj       map[string]interface{}
		fields    []string
		wantVal   int64
		wantFound bool
		wantErr   bool
	}{
		// ---- Basic type coercions at top level ----
		{
			name:      "int64_value",
			obj:       map[string]interface{}{"count": int64(42)},
			fields:    []string{"count"},
			wantVal:   42,
			wantFound: true,
		},
		{
			name:      "float64_value",
			obj:       map[string]interface{}{"count": float64(99)},
			fields:    []string{"count"},
			wantVal:   99,
			wantFound: true,
		},
		{
			name:      "int_value",
			obj:       map[string]interface{}{"count": int(7)},
			fields:    []string{"count"},
			wantVal:   7,
			wantFound: true,
		},
		{
			name:      "float64_with_decimals_truncates",
			obj:       map[string]interface{}{"count": float64(3.9)},
			fields:    []string{"count"},
			wantVal:   3,
			wantFound: true,
		},
		{
			name:      "zero_int64",
			obj:       map[string]interface{}{"count": int64(0)},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: true,
		},
		{
			name:      "negative_int64",
			obj:       map[string]interface{}{"count": int64(-5)},
			fields:    []string{"count"},
			wantVal:   -5,
			wantFound: true,
		},

		// ---- Nested field access ----
		{
			name: "nested_two_levels",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"constraintCount": int64(10),
				},
			},
			fields:    []string{"status", "constraintCount"},
			wantVal:   10,
			wantFound: true,
		},
		{
			name: "nested_three_levels",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"machineReadable": map[string]interface{}{
						"total": float64(25),
					},
				},
			},
			fields:    []string{"status", "machineReadable", "total"},
			wantVal:   25,
			wantFound: true,
		},

		// ---- Not found cases ----
		{
			name:      "missing_key",
			obj:       map[string]interface{}{"other": int64(1)},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name:      "string_value_not_numeric",
			obj:       map[string]interface{}{"count": "not-a-number"},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name:      "nil_value",
			obj:       map[string]interface{}{"count": nil},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name:      "bool_value",
			obj:       map[string]interface{}{"count": true},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name: "nested_intermediate_not_map",
			obj: map[string]interface{}{
				"status": "not-a-map",
			},
			fields:    []string{"status", "count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name: "nested_intermediate_nil",
			obj: map[string]interface{}{
				"status": nil,
			},
			fields:    []string{"status", "count"},
			wantVal:   0,
			wantFound: false,
		},
		{
			name: "nested_missing_intermediate",
			obj: map[string]interface{}{
				"metadata": map[string]interface{}{},
			},
			fields:    []string{"status", "count"},
			wantVal:   0,
			wantFound: false,
		},

		// ---- Edge: empty fields ----
		{
			name:      "no_fields",
			obj:       map[string]interface{}{"count": int64(5)},
			fields:    []string{},
			wantVal:   0,
			wantFound: false,
		},

		// ---- Edge: empty object ----
		{
			name:      "empty_object",
			obj:       map[string]interface{}{},
			fields:    []string{"count"},
			wantVal:   0,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, found, err := getInt64(tt.obj, tt.fields...)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantFound, found, "found mismatch")
			assert.Equal(t, tt.wantVal, val, "value mismatch")
		})
	}
}
