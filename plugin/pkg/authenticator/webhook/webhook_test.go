/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/suzerain-io/placeholder-name/pkg/authentication"
)

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name string

		response authenticationv1.TokenReviewStatus

		wantStatus        authentication.Status
		wantAuthenticated bool
		wantErr           bool
	}{
		{
			name: "Happy",
			response: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "ada@lovelace.com",
					UID:      "abc-123",
					Groups:   []string{"tuna", "fish", "marlin"},
					Extra: map[string]authenticationv1.ExtraValue{
						"doughnut": authenticationv1.ExtraValue([]string{
							"pizza",
							"pasta",
						}),
					},
				},
			},
			wantStatus: authentication.Status{
				User: &authentication.DefaultUser{
					Name:   "ada@lovelace.com",
					UID:    "abc-123",
					Groups: []string{"tuna", "fish", "marlin"},
					Extra: map[string][]string{
						"doughnut": []string{
							"pizza",
							"pasta",
						},
					},
				},
			},
			wantAuthenticated: true,
			wantErr:           false,
		},
		{
			name: "TokenReviewError",
			response: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Error:         "some-error",
			},
			wantErr: true,
		},
		{
			name: "TokenReviewNotAuthenticated",
			response: authenticationv1.TokenReviewStatus{
				Authenticated: false,
			},
			wantErr: true,
		},
	}
	for _, theTest := range tests {
		test := theTest
		t.Run(test.name, func(t *testing.T) {
			clientset := &fake.Clientset{}
			clientset.Fake.AddReactor(
				"create",
				"tokenreviews",
				func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, &authenticationv1.TokenReview{
						Status: test.response,
					}, nil
				},
			)

			w := New(clientset)

			expect := assert.New(t)
			token := "some-token" // TODO(akeesler): validate token passed to clientset!
			status, authenticated, err := w.Authenticate(
				context.Background(),
				authentication.Credential{
					Type:  authentication.TokenCredentialType,
					Token: &token,
				},
			)
			switch {
			case test.wantErr:
				expect.Error(err)
			case !test.wantAuthenticated:
				expect.False(authenticated)
			default:
				expect.Equal(&test.wantStatus, status)
			}

			expect.Equal(1, len(clientset.Actions()))
		})
	}
}
