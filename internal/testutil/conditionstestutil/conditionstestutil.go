// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conditionstestutil

import (
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SortByType(c []metav1.Condition) []metav1.Condition {
	cp := make([]metav1.Condition, len(c))
	copy(cp, c)
	sort.SliceStable(cp, func(i, j int) bool {
		return cp[i].Type < cp[j].Type
	})
	return cp
}

func Replace(originals []metav1.Condition, replacements []metav1.Condition) []metav1.Condition {
	for _, sadReplaceCondition := range replacements {
		for origIndex, origCondition := range originals {
			if origCondition.Type == sadReplaceCondition.Type {
				originals[origIndex] = sadReplaceCondition
				break
			}
		}
	}
	return originals
}
