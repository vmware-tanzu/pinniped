// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authenticators contains authenticator interfaces.
package authenticators

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"
)

// This interface is similar to the k8s token authenticator, but works with username/passwords instead
// of a single token string.
//
// The return values should be as follows.
// 1. For a successful authentication:
//    - A response which includes the username, uid, and groups in the userInfo. The username and uid must not be blank.
//    - true
//    - nil error
// 2. For an unsuccessful authentication, e.g. bad username or password:
//    - nil response
//    - false
//    - nil error
// 3. For an unexpected error, e.g. a network problem:
//    - nil response
//    - false
//    - an error
// Other combinations of return values must be avoided.
//
// See k8s.io/apiserver/pkg/authentication/authenticator/interfaces.go for the token authenticator
// interface, as well as the Response type.
type UserAuthenticator interface {
	AuthenticateUser(ctx context.Context, username, password string) (*Response, bool, error)
}

type Response struct {
	User user.Info
	DN   string
}
