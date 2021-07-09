// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientregistry defines Pinniped's OAuth2/OIDC clients.
package clientregistry

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
)

// Client represents a Pinniped OAuth/OIDC client.
type Client struct {
	fosite.DefaultOpenIDConnectClient
}

func (c Client) GetResponseModes() []fosite.ResponseModeType {
	// For now, all Pinniped clients always support "" (unspecified), "query", and "form_post" response modes.
	return []fosite.ResponseModeType{fosite.ResponseModeDefault, fosite.ResponseModeQuery, fosite.ResponseModeFormPost}
}

// It implements both the base, OIDC, and response_mode client interfaces of Fosite.
var (
	_ fosite.Client              = (*Client)(nil)
	_ fosite.OpenIDConnectClient = (*Client)(nil)
	_ fosite.ResponseModeClient  = (*Client)(nil)
)

// StaticClientManager is a fosite.ClientManager with statically-defined clients.
type StaticClientManager struct{}

var _ fosite.ClientManager = (*StaticClientManager)(nil)

// GetClient returns a static client specified by the given ID.
//
// It returns a fosite.ErrNotFound if an unknown client is specified.
func (StaticClientManager) GetClient(_ context.Context, id string) (fosite.Client, error) {
	switch id {
	case "pinniped-cli":
		return PinnipedCLI(), nil
	default:
		return nil, fosite.ErrNotFound.WithDescription("no such client")
	}
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
//
// This functionality is not supported by the StaticClientManager.
func (StaticClientManager) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return fmt.Errorf("not implemented")
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
//
// This functionality is not supported by the StaticClientManager.
func (StaticClientManager) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return fmt.Errorf("not implemented")
}

// PinnipedCLI returns the static Client corresponding to the Pinniped CLI.
func PinnipedCLI() *Client {
	return &Client{
		DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:           "pinniped-cli",
				Secret:       nil,
				RedirectURIs: []string{"http://127.0.0.1/callback"},
				GrantTypes: fosite.Arguments{
					"authorization_code",
					"refresh_token",
					"urn:ietf:params:oauth:grant-type:token-exchange",
				},
				ResponseTypes: []string{"code"},
				Scopes: fosite.Arguments{
					oidc.ScopeOpenID,
					oidc.ScopeOfflineAccess,
					"profile",
					"email",
					"pinniped:request-audience",
				},
				Audience: nil,
				Public:   true,
			},
			RequestURIs:                       nil,
			JSONWebKeys:                       nil,
			JSONWebKeysURI:                    "",
			RequestObjectSigningAlgorithm:     "",
			TokenEndpointAuthSigningAlgorithm: oidc.RS256,
			TokenEndpointAuthMethod:           "none",
		},
	}
}
