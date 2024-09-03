// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	coretesting "k8s.io/client-go/testing"
)

// ScrubListOptionsForActions ignores certain aspects of Watch Actions which changed in K8s 1.31.
// Because of https://github.com/kubernetes/kubernetes/pull/125560 our test code is busted.
func ScrubListOptionsForActions(t *testing.T, actions []coretesting.Action) []coretesting.Action {
	t.Helper()

	scrubbedActions := make([]coretesting.Action, 0, len(actions))
	for _, action := range actions {
		switch action.GetVerb() {
		case "watch":
			watchAction, ok := action.(coretesting.WatchActionImpl)
			require.True(t, ok)
			watchAction.ListOptions.AllowWatchBookmarks = false
			watchAction.ListOptions.TimeoutSeconds = nil
			scrubbedActions = append(scrubbedActions, watchAction)
		case "list":
			listAction, ok := action.(coretesting.ListActionImpl)
			require.True(t, ok)
			listAction.ListOptions.ResourceVersion = ""
			listAction.ListOptions.TimeoutSeconds = nil
			listAction.ListOptions.Limit = 0
			scrubbedActions = append(scrubbedActions, listAction)
		default:
			scrubbedActions = append(scrubbedActions, action)
		}
	}
	return scrubbedActions
}
