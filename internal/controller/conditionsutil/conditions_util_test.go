// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conditionsutil

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/plog"
)

func TestMergeIDPConditions(t *testing.T) {
	twoHoursAgo := metav1.Time{Time: time.Now().Add(-2 * time.Hour)}
	oneHourAgo := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}
	testTime := metav1.Now()

	tests := []struct {
		name               string
		newConditions      []*metav1.Condition
		conditionsToUpdate *[]metav1.Condition
		observedGeneration int64
		wantResult         bool
		wantLogSnippets    []string
		wantConditions     []metav1.Condition
	}{
		{
			name: "Adding a new condition with status=True returns false",
			newConditions: []*metav1.Condition{
				{
					Type:    "NewType",
					Status:  metav1.ConditionTrue,
					Reason:  "new reason",
					Message: "new message",
				},
			},
			observedGeneration: int64(999),
			conditionsToUpdate: &[]metav1.Condition{},
			wantLogSnippets: []string{
				`"message":"updated condition","type":"NewType","status":"True"`,
			},
			wantConditions: []metav1.Condition{
				{
					Type:               "NewType",
					Status:             metav1.ConditionTrue,
					ObservedGeneration: int64(999),
					LastTransitionTime: testTime,
					Reason:             "new reason",
					Message:            "new message",
				},
			},
			wantResult: false,
		},
		{
			name: "Updating a condition status from False to True returns true",
			newConditions: []*metav1.Condition{
				{
					Type:    "UnchangedType",
					Status:  metav1.ConditionTrue,
					Reason:  "unchanged reason",
					Message: "unchanged message",
				},
				{
					Type:    "FalseToTrueType",
					Status:  metav1.ConditionFalse,
					Reason:  "new reason",
					Message: "new message",
				},
				{
					Type:    "NewType",
					Status:  metav1.ConditionTrue,
					Reason:  "new reason",
					Message: "new message",
				},
			},
			conditionsToUpdate: &[]metav1.Condition{
				{
					Type:               "UnchangedType",
					Status:             metav1.ConditionTrue,
					ObservedGeneration: int64(10),
					LastTransitionTime: twoHoursAgo,
					Reason:             "unchanged reason",
					Message:            "unchanged message",
				},
				{
					Type:               "FalseToTrueType",
					Status:             metav1.ConditionTrue,
					ObservedGeneration: int64(5),
					LastTransitionTime: oneHourAgo,
					Reason:             "old reason",
					Message:            "old message",
				},
			},
			observedGeneration: int64(100),
			wantLogSnippets: []string{
				`"message":"updated condition","type":"UnchangedType","status":"True"`,
				`"message":"updated condition","type":"NewType","status":"True"`,
				`"message":"updated condition","type":"FalseToTrueType","status":"False"`,
			},
			wantConditions: []metav1.Condition{
				{
					Type:               "FalseToTrueType",
					Status:             metav1.ConditionFalse,
					ObservedGeneration: int64(100),
					LastTransitionTime: testTime,
					Reason:             "new reason",
					Message:            "new message",
				},
				{
					Type:               "NewType",
					Status:             metav1.ConditionTrue,
					ObservedGeneration: int64(100),
					LastTransitionTime: testTime,
					Reason:             "new reason",
					Message:            "new message",
				},
				{
					Type:               "UnchangedType",
					Status:             metav1.ConditionTrue,
					ObservedGeneration: int64(100),
					LastTransitionTime: twoHoursAgo,
					Reason:             "unchanged reason",
					Message:            "unchanged message",
				},
			},
			wantResult: true,
		},
		{
			name: "No logs when ObservedGeneration is unchanged",
			newConditions: []*metav1.Condition{
				{
					Type:    "UnchangedType",
					Status:  metav1.ConditionFalse,
					Reason:  "unchanged reason",
					Message: "unchanged message",
				},
			},
			conditionsToUpdate: &[]metav1.Condition{
				{
					Type:               "UnchangedType",
					Status:             metav1.ConditionFalse,
					ObservedGeneration: int64(10),
					LastTransitionTime: twoHoursAgo,
					Reason:             "unchanged reason",
					Message:            "unchanged message",
				},
			},
			observedGeneration: int64(10),
			wantConditions: []metav1.Condition{
				{
					Type:               "UnchangedType",
					Status:             metav1.ConditionFalse,
					ObservedGeneration: int64(10),
					LastTransitionTime: twoHoursAgo,
					Reason:             "unchanged reason",
					Message:            "unchanged message",
				},
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			result := MergeConditions(
				tt.newConditions,
				tt.conditionsToUpdate,
				tt.observedGeneration,
				testTime,
				logger,
			)

			logString := log.String()
			require.Equal(t, len(tt.wantLogSnippets), strings.Count(logString, "\n"))
			for _, wantLog := range tt.wantLogSnippets {
				require.Contains(t, logString, wantLog)
			}
			require.Equal(t, tt.wantResult, result)
			require.Equal(t, tt.wantConditions, *tt.conditionsToUpdate)
		})
	}
}
