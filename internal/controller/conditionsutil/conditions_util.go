// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conditionsutil

import (
	"sort"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/plog"
)

const (
	ReasonSuccess = "Success"
)

// MergeConditions merges conditions into conditionsToUpdate.
// Note that LastTransitionTime refers to the time when the status changed,
// but ObservedGeneration should be the current generation for all conditions, since Pinniped should always check every condition.
// It returns true if any resulting condition has non-true status.
func MergeConditions(
	conditions []*metav1.Condition,
	observedGeneration int64,
	conditionsToUpdate *[]metav1.Condition,
	log plog.MinLogger,
	lastTransitionTime metav1.Time,
) bool {
	for i := range conditions {
		cond := conditions[i].DeepCopy()
		cond.LastTransitionTime = lastTransitionTime
		cond.ObservedGeneration = observedGeneration
		if mergeCondition(conditionsToUpdate, cond) {
			log.Info("updated condition", "type", cond.Type, "status", cond.Status, "reason", cond.Reason, "message", cond.Message)
		}
	}
	sort.SliceStable(*conditionsToUpdate, func(i, j int) bool {
		return (*conditionsToUpdate)[i].Type < (*conditionsToUpdate)[j].Type
	})
	return HadErrorCondition(conditions)
}

// mergeCondition merges a new metav1.Condition into a slice of existing conditions. It returns true
// if the condition has meaningfully changed.
func mergeCondition(existing *[]metav1.Condition, new *metav1.Condition) bool {
	// Find any existing condition with a matching type.
	var old *metav1.Condition
	for i := range *existing {
		if (*existing)[i].Type == new.Type {
			old = &(*existing)[i]
			continue
		}
	}

	// If there is no existing condition of this type, append this one and we're done.
	if old == nil {
		*existing = append(*existing, *new)
		return true
	}

	// Set the LastTransitionTime depending on whether the status has changed.
	new = new.DeepCopy()
	if old.Status == new.Status {
		new.LastTransitionTime = old.LastTransitionTime
	}

	// If anything has actually changed, update the entry and return true.
	if !equality.Semantic.DeepEqual(old, new) {
		*old = *new
		return true
	}

	// Otherwise the entry is already up-to-date.
	return false
}

func HadErrorCondition(conditions []*metav1.Condition) bool {
	for _, c := range conditions {
		if c.Status != metav1.ConditionTrue {
			return true
		}
	}
	return false
}
