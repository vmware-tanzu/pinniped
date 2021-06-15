// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
	require.EqualError(t, err, "not_found")
	require.Zero(t, client)

	client, err = storage.GetClient(context.Background(), "pinniped-cli")
	require.NoError(t, err)
	require.Equal(t, fosite.Arguments{
		"openid",
		"offline_access",
		"profile",
		"email",
		"pinniped:request-audience",
	}, client.GetScopes())
}
