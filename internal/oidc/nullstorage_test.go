// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestNullStorage_GetClient(t *testing.T) {
	storage := NullStorage{}

	client, err := storage.GetClient(context.Background(), "some-other-client")
	require.Equal(t, fosite.ErrNotFound, err)
	require.Zero(t, client)

	client, err = storage.GetClient(context.Background(), "pinniped-cli")
	require.NoError(t, err)
	require.Equal(t,
		&fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:            "pinniped-cli",
				Public:        true,
				RedirectURIs:  []string{"http://127.0.0.1/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"authorization_code"},
				Scopes:        []string{"openid", "profile", "email"},
			},
			TokenEndpointAuthMethod: "none",
		},
		client,
	)
}
