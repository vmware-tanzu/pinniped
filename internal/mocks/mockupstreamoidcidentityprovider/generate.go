// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockupstreamoidcidentityprovider

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockupstreamoidcidentityprovider.go -package=mockupstreamoidcidentityprovider -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/oidc/provider/upstreamprovider UpstreamOIDCIdentityProviderI
