package staticclient

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestClientPinnipedCLI(t *testing.T) {
	require.Zero(t, reflect.TypeOf(PinnipedCLI{}).Size())

	c := &PinnipedCLI{}
	require.Equal(t, "pinniped-cli", c.GetID())
	require.Nil(t, c.GetHashedSecret())
	require.Equal(t, []string{"http://127.0.0.1/callback"}, c.GetRedirectURIs())
	require.Equal(t, fosite.Arguments{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}, c.GetGrantTypes())
	require.Equal(t, fosite.Arguments{"code"}, c.GetResponseTypes())
	require.Equal(t, fosite.Arguments{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "pinniped:request-audience"}, c.GetScopes())
	require.True(t, c.IsPublic())
	require.Nil(t, c.GetAudience())
	require.Nil(t, c.GetRequestURIs())
	require.Nil(t, c.GetJSONWebKeys())
	require.Equal(t, "", c.GetJSONWebKeysURI())
	require.Equal(t, "", c.GetRequestObjectSigningAlgorithm())
	require.Equal(t, "none", c.GetTokenEndpointAuthMethod())
	require.Equal(t, "RS256", c.GetTokenEndpointAuthSigningAlgorithm())

	marshaled, err := json.Marshal(c)
	require.NoError(t, err)
	require.JSONEq(t, `{"id": "pinniped-cli"}`, string(marshaled))

	var unmarshaled PinnipedCLI
	require.EqualError(t, json.Unmarshal([]byte(``), &unmarshaled), `unexpected end of JSON input`)
	require.EqualError(t, json.Unmarshal([]byte(`{}`), &unmarshaled), `unexpected client ID "" (expected "pinniped-cli")`)
	require.EqualError(t, json.Unmarshal([]byte(`{"id": "wrong-id"}`), &unmarshaled), `unexpected client ID "wrong-id" (expected "pinniped-cli")`)
	require.NoError(t, json.Unmarshal([]byte(`{"id": "pinniped-cli"}`), &unmarshaled))
	require.NoError(t, json.Unmarshal([]byte(`{"id": "pinniped-cli", "extra": "value"}`), &unmarshaled))
}
