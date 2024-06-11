// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockcredentialrequest

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockcredentialrequest.go -package=mockcredentialrequest -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/registry/credentialrequest TokenCredentialRequestAuthenticator
