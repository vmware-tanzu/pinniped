/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package authentication contains types for mapping from a credential to a user.
package authentication

import "context"

// TODO(ankeesler): much of this is stolen from Kube...import?

// Authenticator takes in a Credential and spits out
//   1) a yes/no verdict on whether it was able to map this Credential to a User,
//   2) a User, if the answer to #1 was "yes",
//   3) or an error, if there was some non-authentication-related failure.
type Authenticator interface {
	Authenticate(ctx context.Context, cred Credential) (*Status, bool, error)
}

type CredentialType string

const (
	TokenCredentialType = CredentialType("token")
)

// Credential is some sort of (usually) private data that can be used to assert
// a User's identity.
type Credential struct {
	// Type is the type of this Credential (see CredentialType constants).
	Type CredentialType

	// Token is a...token. Ya know, like, a JWT or something.
	// This should be non-nil when Type == TokenCredentialType.
	Token *string
}

// User contains details about a human being that has been authenticated.
type User interface {
	// Name returns a unique identifier for this User.
	GetName() string
	// Groups returns identifiers for the groups to which this User belongs.
	GetGroups() []string
	// Extra() returns a map of other details about this User.
	GetExtra() map[string][]string
}

// Status is the result of an authentication attempt.
type Status struct {
	// Audiences are the parties for which this User is valid.
	Audiences []string
	// User describes the human being that has been authenticated.
	User User
}

// DefaultUser is a trivial implementation of a User.
type DefaultUser struct {
	Name   string
	Groups []string
	Extra  map[string][]string
}

var _ User = &DefaultUser{}

func (du *DefaultUser) GetName() string               { return du.Name }
func (du *DefaultUser) GetGroups() []string           { return du.Groups }
func (du *DefaultUser) GetExtra() map[string][]string { return du.Extra }
