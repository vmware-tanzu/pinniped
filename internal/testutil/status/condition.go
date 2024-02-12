// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package status

import (
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SortConditionsByType(c []metav1.Condition) []metav1.Condition {
	cp := make([]metav1.Condition, len(c))
	copy(cp, c)
	sort.SliceStable(cp, func(i, j int) bool {
		return cp[i].Type < cp[j].Type
	})
	return cp
}

func ReplaceConditions(conditions []metav1.Condition, sadConditions []metav1.Condition) []metav1.Condition {
	for _, sadReplaceCondition := range sadConditions {
		for origIndex, origCondition := range conditions {
			if origCondition.Type == sadReplaceCondition.Type {
				conditions[origIndex] = sadReplaceCondition
				break
			}
		}
	}
	return conditions
}
