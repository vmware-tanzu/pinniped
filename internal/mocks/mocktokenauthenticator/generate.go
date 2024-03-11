// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mocktokenauthenticator

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mocktokenauthenticator.go -package=mocktokenauthenticator -copyright_file=../../../hack/header.txt k8s.io/apiserver/pkg/authentication/authenticator Token
