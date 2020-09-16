/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mocktokenauthenticator

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mocktokenauthenticator.go -package=mocktokenauthenticator -copyright_file=../../../hack/header.txt k8s.io/apiserver/pkg/authentication/authenticator Token
