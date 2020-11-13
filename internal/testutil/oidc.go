// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import "go.pinniped.dev/internal/oidc/provider"

// Test helpers for the OIDC package.

func NewIDPListGetter(upstreamOIDCIdentityProviders ...provider.UpstreamOIDCIdentityProvider) provider.DynamicUpstreamIDPProvider {
	idpProvider := provider.NewDynamicUpstreamIDPProvider()
	idpProvider.SetIDPList(upstreamOIDCIdentityProviders)
	return idpProvider
}

// Declare a separate type from the production code to ensure that the state param's contents was serialized
// in the format that we expect, with the json keys that we expect, etc. This also ensure that the order of
// the serialized fields is the same, which doesn't really matter expect that we can make simpler equality
// assertions about the redirect URL in this test.
type ExpectedUpstreamStateParamFormat struct {
	P string `json:"p"`
	N string `json:"n"`
	C string `json:"c"`
	K string `json:"k"`
	V string `json:"v"`
}
