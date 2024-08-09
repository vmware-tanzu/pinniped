// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conditionsutil

import (
	"slices"
	"sort"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
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

// MergeConditions merges newConditions into existingConditionsToUpdate.
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
		newCondition := newConditions[i].DeepCopy()
		newCondition.LastTransitionTime = lastTransitionTime
		newCondition.ObservedGeneration = observedGeneration
		if mergeCondition(existingConditionsToUpdate, newCondition) {
			log.Info("updated condition",
				"type", newCondition.Type,
				"status", newCondition.Status,
				"reason", newCondition.Reason,
				"message", newCondition.Message)
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
	index := slices.IndexFunc(*existingConditionsToUpdate, func(condition metav1.Condition) bool {
		return newCondition.Type == condition.Type
	})

	var existingCondition *metav1.Condition
	if index < 0 {
		// If there is no existing condition of this type, append this one and we're done.
		*existingConditionsToUpdate = append(*existingConditionsToUpdate, *newCondition)
		return true
	}

	// Get a pointer to the existing condition
	existingCondition = &(*existingConditionsToUpdate)[index]

	// If the status has not changed, preserve the original lastTransitionTime
	if newCondition.Status == existingCondition.Status {
		newCondition.LastTransitionTime = existingCondition.LastTransitionTime
	}

	changed := !apiequality.Semantic.DeepEqual(existingCondition, newCondition)
	*existingCondition = *newCondition
	return changed
}

func HadErrorCondition(conditions []*metav1.Condition) bool {
	return slices.ContainsFunc(conditions, func(condition *metav1.Condition) bool {
		return condition.Status != metav1.ConditionTrue
	})
}
