// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package clientregistry defines Pinniped's OAuth2/OIDC clients.
package clientregistry

import (
	"context"
	"fmt"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	supervisorclient "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/plog"
)

// Client represents a Pinniped OAuth/OIDC client. It can be the static pinniped-cli client
// or a dynamic client defined by an OIDCClient CR.
type Client struct {
	fosite.DefaultOpenIDConnectClient
}

// Client implements the base, OIDC, and response_mode client interfaces of Fosite.
var (
	_ fosite.Client              = (*Client)(nil)
	_ fosite.OpenIDConnectClient = (*Client)(nil)
	_ fosite.ResponseModeClient  = (*Client)(nil)
)

func (c *Client) GetResponseModes() []fosite.ResponseModeType {
	if c.ID == oidcapi.ClientIDPinnipedCLI {
		// The pinniped-cli client supports "" (unspecified), "query", and "form_post" response modes.
		return []fosite.ResponseModeType{fosite.ResponseModeDefault, fosite.ResponseModeQuery, fosite.ResponseModeFormPost}
	}
	// For now, all other clients support only "" (unspecified) and "query" response modes.
	return []fosite.ResponseModeType{fosite.ResponseModeDefault, fosite.ResponseModeQuery}
}

// ClientManager is a fosite.ClientManager with a statically-defined client and with dynamically-defined clients.
type ClientManager struct {
	oidcClientsClient supervisorclient.OIDCClientInterface
	storage           *oidcclientsecretstorage.OIDCClientSecretStorage
	minBcryptCost     int
}

var _ fosite.ClientManager = (*ClientManager)(nil)

func NewClientManager(
	oidcClientsClient supervisorclient.OIDCClientInterface,
	storage *oidcclientsecretstorage.OIDCClientSecretStorage,
	minBcryptCost int,
) *ClientManager {
	return &ClientManager{
		oidcClientsClient: oidcClientsClient,
		storage:           storage,
		minBcryptCost:     minBcryptCost,
	}
}

// GetClient returns the client specified by the given ID.
//
// It returns a fosite.ErrNotFound if an unknown client is specified.
// Other errors returned are plain errors, because fosite will wrap them into a new ErrInvalidClient error and
// use the plain error's text as that error's debug message (see client_authentication.go in fosite).
func (m *ClientManager) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if id == oidcapi.ClientIDPinnipedCLI {
		// Return the static client. No lookups needed.
		return PinnipedCLI(), nil
	}

	if !strings.HasPrefix(id, oidcapi.ClientIDRequiredOIDCClientPrefix) {
		// It shouldn't really be possible to find this OIDCClient because the OIDCClient CRD validates the name prefix
		// upon create, but just in case, don't even try to lookup clients which lack the required name prefix.
		return nil, fosite.ErrNotFound.WithDescription("no such client")
	}

	// Try to look up an OIDCClient with the given client ID (which will be the Name of the OIDCClient).
	oidcClient, err := m.oidcClientsClient.Get(ctx, id, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, fosite.ErrNotFound.WithDescription("no such client")
	}
	if err != nil {
		// Log the error so an admin can see why the lookup failed at the time of the request.
		plog.Error("OIDC client lookup GetClient() failed to get OIDCClient", err, "clientID", id)
		return nil, fmt.Errorf("failed to get client %q", id)
	}

	// Try to find the corresponding client secret storage Secret.
	storageSecret, err := m.storage.GetStorageSecret(ctx, oidcClient.UID)
	if err != nil {
		// Log the error so an admin can see why the lookup failed at the time of the request.
		plog.Error("OIDC client lookup GetClient() failed to get storage secret for OIDCClient", err, "clientID", id)
		return nil, fmt.Errorf("failed to get storage secret for client %q", id)
	}

	// Check if the OIDCClient and its corresponding Secret are valid.
	valid, conditions, clientSecrets := oidcclientvalidator.Validate(oidcClient, storageSecret, m.minBcryptCost)
	if !valid {
		// Log the conditions so an admin can see exactly what was invalid at the time of the request.
		plog.Debug("OIDC client lookup GetClient() found an invalid client", "clientID", id, "conditions", conditions)
		return nil, fmt.Errorf("client %q exists but is invalid or not ready", id)
	}

	// Everything is valid, so return the client. Note that it has at least one client secret to be considered valid.
	return oidcClientCRToFositeClient(oidcClient, clientSecrets), nil
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
//
// This functionality is not supported by the ClientManager.
func (*ClientManager) ClientAssertionJWTValid(_ctx context.Context, _jti string) error {
	return fmt.Errorf("not implemented")
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
//
// This functionality is not supported by the ClientManager.
func (*ClientManager) SetClientAssertionJWT(_ctx context.Context, _jti string, _exp time.Time) error {
	return fmt.Errorf("not implemented")
}

// PinnipedCLI returns the static Client corresponding to the Pinniped CLI.
func PinnipedCLI() *Client {
	return &Client{
		DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:           oidcapi.ClientIDPinnipedCLI,
				Secret:       nil,
				RedirectURIs: []string{"http://127.0.0.1/callback"},
				GrantTypes: fosite.Arguments{
					oidcapi.GrantTypeAuthorizationCode,
					oidcapi.GrantTypeRefreshToken,
					oidcapi.GrantTypeTokenExchange,
				},
				ResponseTypes: []string{"code"},
				Scopes: fosite.Arguments{
					oidcapi.ScopeOpenID,
					oidcapi.ScopeOfflineAccess,
					oidcapi.ScopeProfile,
					oidcapi.ScopeEmail,
					oidcapi.ScopeRequestAudience,
					oidcapi.ScopeUsername,
					oidcapi.ScopeGroups,
				},
				Audience: nil,
				Public:   true,
			},
			RequestURIs:                       nil,
			JSONWebKeys:                       nil,
			JSONWebKeysURI:                    "",
			RequestObjectSigningAlgorithm:     "",
			TokenEndpointAuthSigningAlgorithm: coreosoidc.RS256,
			TokenEndpointAuthMethod:           "none",
		},
	}
}

func oidcClientCRToFositeClient(oidcClient *configv1alpha1.OIDCClient, clientSecrets []string) *Client {
	return &Client{
		DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID: oidcClient.Name,
				// We set RotatedSecrets, but we don't need to also set Secret because the client_authentication.go code
				// will always call the hasher on the empty Secret first, and the bcrypt hasher will always fail very
				// quickly (ErrHashTooShort error), and then client_authentication.go will move on to using the
				// RotatedSecrets instead.
				RotatedSecrets: stringSliceToByteSlices(clientSecrets),
				RedirectURIs:   redirectURIsToStrings(oidcClient.Spec.AllowedRedirectURIs),
				GrantTypes:     grantTypesToArguments(oidcClient.Spec.AllowedGrantTypes),
				ResponseTypes:  []string{"code"},
				Scopes:         scopesToArguments(oidcClient.Spec.AllowedScopes),
				Audience:       nil,
				Public:         false,
			},
			RequestURIs:                       nil,
			JSONWebKeys:                       nil,
			JSONWebKeysURI:                    "",
			RequestObjectSigningAlgorithm:     "",
			TokenEndpointAuthSigningAlgorithm: coreosoidc.RS256,
			TokenEndpointAuthMethod:           "client_secret_basic",
		},
	}
}

func scopesToArguments(scopes []configv1alpha1.Scope) fosite.Arguments {
	a := make(fosite.Arguments, len(scopes))
	for i, scope := range scopes {
		a[i] = string(scope)
	}
	return a
}

func grantTypesToArguments(grantTypes []configv1alpha1.GrantType) fosite.Arguments {
	a := make(fosite.Arguments, len(grantTypes))
	for i, grantType := range grantTypes {
		a[i] = string(grantType)
	}
	return a
}

func redirectURIsToStrings(uris []configv1alpha1.RedirectURI) []string {
	s := make([]string, len(uris))
	for i, uri := range uris {
		s[i] = string(uri)
	}
	return s
}

func stringSliceToByteSlices(s []string) [][]byte {
	b := make([][]byte, len(s))
	for i, str := range s {
		b[i] = []byte(str)
	}
	return b
}
