// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"

	"github.com/ory/fosite/handler/openid"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	testing2 "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/psession"
)

func NewFakePinnipedSession() *psession.PinnipedSession {
	return &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims:    nil,
			Headers:   nil,
			ExpiresAt: nil,
			Username:  "snorlax",
			Subject:   "panda",
		},
		Custom: &psession.CustomSessionData{
			ProviderUID:  "fake-provider-uid",
			ProviderType: "fake-provider-type",
			ProviderName: "fake-provider-name",
			OIDC: &psession.OIDCSessionData{
				UpstreamRefreshToken: "fake-upstream-refresh-token",
				UpstreamSubject:      "some-subject",
				UpstreamIssuer:       "some-issuer",
			},
		},
	}
}

func LogActualJSONFromCreateAction(t *testing.T, client *fake.Clientset, actionIndex int) {
	t.Log("actual value of CreateAction secret data", string(client.Actions()[actionIndex].(testing2.CreateActionImpl).Object.(*v1.Secret).Data["pinniped-storage-data"]))
}

func LogActualJSONFromUpdateAction(t *testing.T, client *fake.Clientset, actionIndex int) {
	t.Log("actual value of UpdateAction secret data", string(client.Actions()[actionIndex].(testing2.UpdateActionImpl).Object.(*v1.Secret).Data["pinniped-storage-data"]))
}
