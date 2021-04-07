// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package ldap contains common LDAP functionality needed by Pinniped.
package ldap

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// This interface is similar to the k8s token authenticator, but works with username/passwords instead
// of a single token string.
//
// See k8s.io/apiserver/pkg/authentication/authenticator/interfaces.go for the token authenticator
// interface, as well as the Response type.
type UserAuthenticator interface {
	AuthenticateUser(ctx context.Context, username, password string) (*authenticator.Response, bool, error)
}
