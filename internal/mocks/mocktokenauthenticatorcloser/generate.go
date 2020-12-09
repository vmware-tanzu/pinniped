// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mocktokenauthenticatorcloser

import (
	"k8s.io/apiserver/pkg/authentication/authenticator"

	pinnipedauthenticator "go.pinniped.dev/internal/controller/authenticator"
)

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mocktokenauthenticatorcloser.go -package=mocktokenauthenticatorcloser -copyright_file=../../../hack/header.txt . TokenAuthenticatorCloser

// TokenAuthenticatorCloser is a type that can authenticate tokens and be closed idempotently.
//
// This type is slightly different from io.Closer, because io.Closer can return an error and is not
// necessarily idempotent.
type TokenAuthenticatorCloser interface {
	authenticator.Token
	pinnipedauthenticator.Closer
}
