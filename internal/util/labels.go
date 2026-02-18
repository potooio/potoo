package util

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// MatchesLabelSelector reports whether the given labels satisfy the selector.
// A nil selector matches everything. Returns false on parse errors.
func MatchesLabelSelector(selector *metav1.LabelSelector, lbls map[string]string) bool {
	if selector == nil {
		return true
	}
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return sel.Matches(labels.Set(lbls))
}
