package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInt64_Int64Value(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"constraintCount": int64(42),
		},
	}

	val, found, err := getInt64(obj, "status", "constraintCount")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(42), val)
}

func TestGetInt64_Float64Value(t *testing.T) {
	// JSON unmarshaling often produces float64 for numbers
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"count": float64(15),
		},
	}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(15), val)
}

func TestGetInt64_IntValue(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"total": int(7),
		},
	}

	val, found, err := getInt64(obj, "status", "total")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(7), val)
}

func TestGetInt64_MissingKey(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{},
	}

	val, found, err := getInt64(obj, "status", "missing")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_MissingNestedPath(t *testing.T) {
	obj := map[string]interface{}{}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_InvalidIntermediateType(t *testing.T) {
	obj := map[string]interface{}{
		"status": "not-a-map",
	}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_UnsupportedValueType(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"count": "not-a-number",
		},
	}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_DeeplyNested(t *testing.T) {
	obj := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": int64(99),
			},
		},
	}

	val, found, err := getInt64(obj, "a", "b", "c")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(99), val)
}

func TestGetInt64_SingleField(t *testing.T) {
	obj := map[string]interface{}{
		"count": int64(5),
	}

	val, found, err := getInt64(obj, "count")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(5), val)
}

func TestGetInt64_NilValue(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"count": nil,
		},
	}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_EmptyFields(t *testing.T) {
	obj := map[string]interface{}{
		"value": int64(10),
	}

	// No fields provided -- should return 0, false
	val, found, err := getInt64(obj)
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), val)
}

func TestGetInt64_ZeroValue(t *testing.T) {
	obj := map[string]interface{}{
		"status": map[string]interface{}{
			"count": int64(0),
		},
	}

	val, found, err := getInt64(obj, "status", "count")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(0), val)
}
