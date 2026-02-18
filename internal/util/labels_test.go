package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMatchesLabelSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector *metav1.LabelSelector
		labels   map[string]string
		expected bool
	}{
		{
			name:     "nil selector matches all",
			selector: nil,
			labels:   map[string]string{"app": "foo"},
			expected: true,
		},
		{
			name:     "empty selector matches all",
			selector: &metav1.LabelSelector{},
			labels:   map[string]string{"app": "foo"},
			expected: true,
		},
		{
			name: "matching labels",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   map[string]string{"app": "foo", "version": "v1"},
			expected: true,
		},
		{
			name: "non-matching labels",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   map[string]string{"app": "bar"},
			expected: false,
		},
		{
			name: "missing label",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   map[string]string{"version": "v1"},
			expected: false,
		},
		{
			name: "nil labels with non-nil selector",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
			labels:   nil,
			expected: false,
		},
		{
			name: "In operator - match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
				},
			},
			labels:   map[string]string{"env": "prod"},
			expected: true,
		},
		{
			name: "In operator - no match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
				},
			},
			labels:   map[string]string{"env": "dev"},
			expected: false,
		},
		{
			name: "NotIn operator - match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"prod"}},
				},
			},
			labels:   map[string]string{"env": "dev"},
			expected: true,
		},
		{
			name: "NotIn operator - no match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"prod"}},
				},
			},
			labels:   map[string]string{"env": "prod"},
			expected: false,
		},
		{
			name: "Exists operator - match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpExists},
				},
			},
			labels:   map[string]string{"env": "anything"},
			expected: true,
		},
		{
			name: "Exists operator - no match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpExists},
				},
			},
			labels:   map[string]string{"app": "foo"},
			expected: false,
		},
		{
			name: "DoesNotExist operator - match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			labels:   map[string]string{"app": "foo"},
			expected: true,
		},
		{
			name: "DoesNotExist operator - no match",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			labels:   map[string]string{"env": "prod"},
			expected: false,
		},
		{
			name: "combined MatchLabels and MatchExpressions",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
				},
			},
			labels:   map[string]string{"app": "web", "env": "prod"},
			expected: true,
		},
		{
			name: "combined - MatchLabels pass but MatchExpressions fail",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
			labels:   map[string]string{"app": "web", "env": "dev"},
			expected: false,
		},
		{
			name: "invalid operator returns false",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOperator("BadOp"), Values: []string{"x"}},
				},
			},
			labels:   map[string]string{"env": "x"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesLabelSelector(tt.selector, tt.labels)
			assert.Equal(t, tt.expected, result)
		})
	}
}
