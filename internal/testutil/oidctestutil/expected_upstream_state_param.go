// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/stateparam"
)

// ExpectedUpstreamStateParamFormat is a separate type from the production code to ensure that the state
// param's contents was serialized in the format that we expect, with the json keys that we expect, etc.
// This also ensure that the order of the serialized fields is the same, which doesn't really matter
// except that we can make simpler equality assertions about the redirect URL in tests.
type ExpectedUpstreamStateParamFormat struct {
	P string `json:"p"`
	U string `json:"u"`
	T string `json:"t"`
	N string `json:"n"`
	C string `json:"c"`
	K string `json:"k"`
	V string `json:"v"`
}

type UpstreamStateParamBuilder ExpectedUpstreamStateParamFormat

func (b *UpstreamStateParamBuilder) Build(t *testing.T, stateEncoder *securecookie.SecureCookie) stateparam.Encoded {
	state, err := stateEncoder.Encode("s", b)
	require.NoError(t, err)
	return stateparam.Encoded(state)
}

func (b *UpstreamStateParamBuilder) WithAuthorizeRequestParams(params string) *UpstreamStateParamBuilder {
	b.P = params
	return b
}

func (b *UpstreamStateParamBuilder) WithNonce(nonce string) *UpstreamStateParamBuilder {
	b.N = nonce
	return b
}

func (b *UpstreamStateParamBuilder) WithCSRF(csrf string) *UpstreamStateParamBuilder {
	b.C = csrf
	return b
}

func (b *UpstreamStateParamBuilder) WithPKCE(pkce string) *UpstreamStateParamBuilder {
	b.K = pkce
	return b
}

func (b *UpstreamStateParamBuilder) WithUpstreamIDPType(upstreamIDPType idpdiscoveryv1alpha1.IDPType) *UpstreamStateParamBuilder {
	b.T = string(upstreamIDPType)
	return b
}

func (b *UpstreamStateParamBuilder) WithUpstreamIDPName(upstreamIDPName string) *UpstreamStateParamBuilder {
	b.U = upstreamIDPName
	return b
}

func (b *UpstreamStateParamBuilder) WithStateVersion(version string) *UpstreamStateParamBuilder {
	b.V = version
	return b
}
