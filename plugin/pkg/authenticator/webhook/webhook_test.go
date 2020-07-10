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
	token := "some-token"

	tests := []struct {
		name string

		cred authentication.Credential

		response runtime.Object

		wantRequest       runtime.Object
		wantStatus        authentication.Status
		wantAuthenticated bool
		wantErr           bool
	}{
		{
			name: "Happy",
			cred: authentication.Credential{
				Type:  authentication.TokenCredentialType,
				Token: &token,
			},
			response: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
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
			},
			wantRequest: &authenticationv1.TokenReview{
				Spec: authenticationv1.TokenReviewSpec{
					Token: "some-token",
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
			name: "InvalidCredentialType",
			cred: authentication.Credential{
				Type: "certificate",
			},
		},
		{
			name: "TokenReviewError",
			cred: authentication.Credential{
				Type:  authentication.TokenCredentialType,
				Token: &token,
			},
			response: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Error:         "some-error",
				},
			},
			wantRequest: &authenticationv1.TokenReview{
				Spec: authenticationv1.TokenReviewSpec{
					Token: "some-token",
				},
			},
			wantErr: true,
		},
		{
			name: "TokenReviewNotAuthenticated",
			cred: authentication.Credential{
				Type:  authentication.TokenCredentialType,
				Token: &token,
			},
			response: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Error:         "some-error",
				},
			},
			wantRequest: &authenticationv1.TokenReview{
				Spec: authenticationv1.TokenReviewSpec{
					Token: "some-token",
				},
			},
			wantErr: true,
		},
	}
	for _, theTest := range tests {
		test := theTest
		t.Run(test.name, func(t *testing.T) {
			expect := assert.New(t)

			clientset := &fake.Clientset{}
			clientset.Fake.AddReactor(
				"create",
				"tokenreviews",
				func(action kubetesting.Action) (bool, runtime.Object, error) {
					createAction := action.(kubetesting.CreateActionImpl)
					expect.Equal(test.wantRequest, createAction.Object)
					return true, test.response, nil
				},
			)

			w := New(clientset)

			status, authenticated, err := w.Authenticate(
				context.Background(),
				&test.cred,
			)
			switch {
			case test.wantErr:
				expect.Error(err)
				expect.Equal(1, len(clientset.Actions()))
			case !test.wantAuthenticated:
				expect.False(authenticated)
			default:
				expect.Equal(&test.wantStatus, status)
				expect.Equal(1, len(clientset.Actions()))
			}
		})
	}
}
