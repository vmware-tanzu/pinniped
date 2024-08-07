// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conditionsutil

import (
	"sort"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/plog"
)

// Some common reasons and messages shared by conditions of various resources.
const (
	ReasonSuccess            = "Success"
	ReasonNotReady           = "NotReady"
	ReasonUnableToValidate   = "UnableToValidate"
	ReasonUnableToDialServer = "UnableToDialServer"
	ReasonInvalidIssuerURL   = "InvalidIssuerURL"

	MessageUnableToValidate = "unable to validate; see other conditions for details"
)

// MergeConditions merges conditions into conditionsToUpdate.
// Note that lastTransitionTime refers to the time when the status changed,
// but observedGeneration should be the current generation for all conditions,
// since Pinniped should always check every condition.
// It returns true if any resulting condition has non-true status.
func MergeConditions(
	newConditions []*metav1.Condition,
	existingConditionsToUpdate *[]metav1.Condition,
	observedGeneration int64,
	lastTransitionTime metav1.Time,
	log plog.MinLogger,
) bool {
	for i := range newConditions {
		cond := newConditions[i].DeepCopy()
		cond.LastTransitionTime = lastTransitionTime
		cond.ObservedGeneration = observedGeneration
		if mergeCondition(existingConditionsToUpdate, cond) {
			log.Info("updated condition",
				"type", cond.Type,
				"status", cond.Status,
				"reason", cond.Reason,
				"message", cond.Message)
		}
	}
	sort.SliceStable(*existingConditionsToUpdate, func(i, j int) bool {
		return (*existingConditionsToUpdate)[i].Type < (*existingConditionsToUpdate)[j].Type
	})
	return HadErrorCondition(newConditions)
}

// mergeCondition merges a new metav1.Condition into a slice of existing conditions. It returns true
// if something other than the LastTransitionTime has been updated.
func mergeCondition(existingConditionsToUpdate *[]metav1.Condition, newCondition *metav1.Condition) bool {
	// Find any existing condition with a matching type.
	var old *metav1.Condition
	for i := range *existingConditionsToUpdate {
		if (*existingConditionsToUpdate)[i].Type == newCondition.Type {
			old = &(*existingConditionsToUpdate)[i]
			continue
		}
	}

	// If there is no existing condition of this type, append this one and we're done.
	if old == nil {
		*existingConditionsToUpdate = append(*existingConditionsToUpdate, *newCondition)
		return true
	}

	// Set the LastTransitionTime depending on whether the status has changed.
	newCondition = newCondition.DeepCopy()
	if old.Status == newCondition.Status {
		newCondition.LastTransitionTime = old.LastTransitionTime
	}

	// If anything has actually changed, update the entry and return true.
	if !equality.Semantic.DeepEqual(old, newCondition) {
		*old = *newCondition
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
