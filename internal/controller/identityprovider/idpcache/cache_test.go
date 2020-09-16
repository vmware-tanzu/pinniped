// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idpcache

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/suzerain-io/pinniped/internal/controllerlib"
	"github.com/suzerain-io/pinniped/internal/mocks/mocktokenauthenticator"
)

func TestCache(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tests := []struct {
		name               string
		mockAuthenticators map[controllerlib.Key]func(*mocktokenauthenticator.MockToken)
		wantResponse       *authenticator.Response
		wantAuthenticated  bool
		wantErr            string
	}{
		{
			name:    "no IDPs",
			wantErr: "no identity providers are loaded",
		},
		{
			name: "multiple IDPs",
			mockAuthenticators: map[controllerlib.Key]func(mockToken *mocktokenauthenticator.MockToken){
				controllerlib.Key{Namespace: "foo", Name: "idp-one"}: nil,
				controllerlib.Key{Namespace: "foo", Name: "idp-two"}: nil,
			},
			wantErr: "could not uniquely match against an identity provider",
		},
		{
			name: "success",
			mockAuthenticators: map[controllerlib.Key]func(mockToken *mocktokenauthenticator.MockToken){
				controllerlib.Key{
					Namespace: "foo",
					Name:      "idp-one",
				}: func(mockToken *mocktokenauthenticator.MockToken) {
					mockToken.EXPECT().AuthenticateToken(ctx, "test-token").Return(
						&authenticator.Response{User: &user.DefaultInfo{Name: "test-user"}},
						true,
						nil,
					)
				},
			},
			wantResponse:      &authenticator.Response{User: &user.DefaultInfo{Name: "test-user"}},
			wantAuthenticated: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cache := New()
			require.NotNil(t, cache)
			require.Implements(t, (*authenticator.Token)(nil), cache)

			for key, mockFunc := range tt.mockAuthenticators {
				mockToken := mocktokenauthenticator.NewMockToken(ctrl)
				if mockFunc != nil {
					mockFunc(mockToken)
				}
				cache.Store(key, mockToken)
			}

			require.Equal(t, len(tt.mockAuthenticators), len(cache.Keys()))

			resp, authenticated, err := cache.AuthenticateToken(ctx, "test-token")
			require.Equal(t, tt.wantResponse, resp)
			require.Equal(t, tt.wantAuthenticated, authenticated)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, key := range cache.Keys() {
				cache.Delete(key)
			}
			require.Zero(t, len(cache.Keys()))
		})
	}
}
