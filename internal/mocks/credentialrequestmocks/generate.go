// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package credentialrequestmocks

//go:generate go run -v go.uber.org/mock/mockgen  -destination=credentialrequestmocks.go -package=credentialrequestmocks -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/registry/credentialrequest TokenCredentialRequestAuthenticator
