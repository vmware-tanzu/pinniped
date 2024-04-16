// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/clientregistry"
)

func TestDefaultLifespans(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	require.Equal(t, 90*time.Minute, c.UpstreamStateParamLifespan)
	require.Equal(t, 10*time.Minute, c.AuthorizeCodeLifespan)
	require.Equal(t, 2*time.Minute, c.AccessTokenLifespan)
	require.Equal(t, 2*time.Minute, c.IDTokenLifespan)
	require.Equal(t, 9*time.Hour, c.RefreshTokenLifespan)
}

func TestStorageLifetimes(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	// These are currently hard-coded.
	require.Equal(t, 9*time.Hour+10*time.Minute, c.AuthorizationCodeSessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.PKCESessionStorageLifetime(nil))
	require.Equal(t, 11*time.Minute, c.OIDCSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.AccessTokenSessionStorageLifetime(nil))
	require.Equal(t, 9*time.Hour+2*time.Minute, c.RefreshTokenSessionStorageLifetime(nil))
}

func TestOverrideDefaultAccessTokenLifespan(t *testing.T) {
	c := DefaultOIDCTimeoutsConfiguration()

	// We are not yet overriding access token lifetimes.
	doOverride, newLifespan := c.OverrideDefaultAccessTokenLifespan(nil)
	require.Equal(t, false, doOverride)
	require.Equal(t, time.Duration(0), newLifespan)
}

func TestOverrideIDTokenLifespan(t *testing.T) {
	tests := []struct {
		name          string
		accessRequest fosite.AccessRequester
		wantOverride  bool
		wantLifespan  time.Duration
	}{
		{
			name: "the client does not override the default ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 0, // 0 means use the default, so this is not an override
					},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
		{
			name: "the client overrides the default ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 42 * time.Second,
					},
				},
			},
			wantOverride: true,
			wantLifespan: 42 * time.Second,
		},
		{
			name: "the client overrides the default ID token lifespan, but the request is for the token exchange, so the override is ignored",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
				Request: fosite.Request{
					Client: &clientregistry.Client{
						IDTokenLifetimeConfiguration: 42 * time.Second,
					},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
		{
			name: "the client is not the expected data type (which shouldn't really happen), so it is assumed to not override the ID token lifespan",
			accessRequest: &fosite.AccessRequest{
				GrantTypes: fosite.Arguments{"foo"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{},
				},
			},
			wantOverride: false,
			wantLifespan: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := DefaultOIDCTimeoutsConfiguration()

			doOverride, newLifespan := c.OverrideDefaultIDTokenLifespan(tt.accessRequest)
			require.Equal(t, tt.wantOverride, doOverride)
			require.Equal(t, tt.wantLifespan, newLifespan)
		})
	}
}
