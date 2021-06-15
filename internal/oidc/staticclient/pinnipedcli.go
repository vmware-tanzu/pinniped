// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package staticclient

import (
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"gopkg.in/square/go-jose.v2"
)

const ClientIDPinnipedCLI = "pinniped-cli"

type PinnipedCLI struct{}

// Implement methods of fosite.Client:
var _ fosite.Client = &PinnipedCLI{}

func (c *PinnipedCLI) GetID() string             { return ClientIDPinnipedCLI }
func (c *PinnipedCLI) GetHashedSecret() []byte   { return nil }
func (c *PinnipedCLI) GetRedirectURIs() []string { return []string{"http://127.0.0.1/callback"} }
func (c *PinnipedCLI) GetGrantTypes() fosite.Arguments {
	return fosite.Arguments{
		"authorization_code",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
}
func (c *PinnipedCLI) GetResponseTypes() fosite.Arguments { return []string{"code"} }
func (c *PinnipedCLI) GetScopes() fosite.Arguments {
	return fosite.Arguments{
		oidc.ScopeOpenID,
		oidc.ScopeOfflineAccess,
		"profile",
		"email",
		"pinniped:request-audience",
	}
}
func (c *PinnipedCLI) IsPublic() bool                { return true }
func (c *PinnipedCLI) GetAudience() fosite.Arguments { return nil }

// Implement methods of fosite.OpenIDConnectClient:
var _ fosite.OpenIDConnectClient = &PinnipedCLI{}

func (c *PinnipedCLI) GetRequestURIs() []string                     { return nil }
func (c *PinnipedCLI) GetJSONWebKeys() *jose.JSONWebKeySet          { return nil }
func (c *PinnipedCLI) GetJSONWebKeysURI() string                    { return "" }
func (c *PinnipedCLI) GetRequestObjectSigningAlgorithm() string     { return "" }
func (c *PinnipedCLI) GetTokenEndpointAuthMethod() string           { return "none" }
func (c *PinnipedCLI) GetTokenEndpointAuthSigningAlgorithm() string { return oidc.RS256 }

// Implement methods of json.Marshaler and json.Unmarshaler:
var (
	_ json.Marshaler   = &PinnipedCLI{}
	_ json.Unmarshaler = &PinnipedCLI{}
)

func (c *PinnipedCLI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID string `json:"id"`
	}{
		ID: ClientIDPinnipedCLI,
	})
}

func (c *PinnipedCLI) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ID != ClientIDPinnipedCLI {
		return fmt.Errorf("unexpected client ID %q (expected %q)", decoded.ID, ClientIDPinnipedCLI)
	}
	return nil
}
