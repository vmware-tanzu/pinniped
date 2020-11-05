// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/oidcclient/state"
	"go.pinniped.dev/test/library"
)

func TestSupervisorLogin(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create downstream OIDC provider (i.e., update supervisor with OIDC provider).
	// TODO: these env vars might not be set, perform similar loop as discovery test?
	scheme := "http"
	addr := env.SupervisorHTTPAddress
	caBundle := ""
	path := "/some/path"
	issuer := fmt.Sprintf("https://%s%s", addr, path)
	_, _ = requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(
		ctx,
		t,
		scheme,
		addr,
		caBundle,
		issuer,
		client,
	)

	// Create HTTP client.
	httpClient := newHTTPClient(t, caBundle, nil)
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// Don't follow any redirects right now, since we simply want to validate that our auth endpoint
		// redirects us.
		return http.ErrUseLastResponse
	}

	// Declare the downstream auth endpoint url we will use.
	downstreamAuthURL := makeDownstreamAuthURL(t, scheme, addr, path)

	// Make request to auth endpoint - should fail, since we have no upstreams.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downstreamAuthURL, nil)
	require.NoError(t, err)
	rsp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer rsp.Body.Close()
	require.Equal(t, http.StatusUnprocessableEntity, rsp.StatusCode)

	// Create upstream OIDC provider.
	// TODO: this is where the new UpstreamOIDCProvider CRD might go.
	upstreamIssuer := env.OIDCUpstream.Issuer
	upstreamClientID := env.OIDCUpstream.ClientID
	upstreamRedirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", env.OIDCUpstream.LocalhostPort)

	// Make request to authorize endpoint - should pass, since we now have an upstream.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, downstreamAuthURL, nil)
	require.NoError(t, err)
	rsp, err = httpClient.Do(req)
	require.NoError(t, err)
	defer rsp.Body.Close()
	require.Equal(t, http.StatusFound, rsp.StatusCode)
	requireValidRedirectLocation(
		ctx,
		t,
		upstreamIssuer,
		upstreamClientID,
		upstreamRedirectURI,
		rsp.Header.Get("Location"),
	)
}

func makeDownstreamAuthURL(t *testing.T, scheme, addr, path string) string {
	t.Helper()
	downstreamOAuth2Config := oauth2.Config{
		// This is the hardcoded public client that the supervisor supports.
		ClientID: "pinniped-cli",
		Endpoint: oauth2.Endpoint{
			AuthURL: fmt.Sprintf("%s://%s%s/oauth2/authorize", scheme, addr, path),
		},
		// This is the hardcoded downstream redirect URI that the supervisor supports.
		RedirectURL: "http://127.0.0.1/callback",
		Scopes:      []string{"openid"},
	}
	state, nonce, pkce := generateAuthRequestParams(t)
	return downstreamOAuth2Config.AuthCodeURL(
		state.String(),
		nonce.Param(),
		pkce.Challenge(),
		pkce.Method(),
	)
}

func generateAuthRequestParams(t *testing.T) (state.State, nonce.Nonce, pkce.Code) {
	t.Helper()
	state, err := state.Generate()
	require.NoError(t, err)
	nonce, err := nonce.Generate()
	require.NoError(t, err)
	pkce, err := pkce.Generate()
	require.NoError(t, err)
	return state, nonce, pkce
}

func requireValidRedirectLocation(
	ctx context.Context,
	t *testing.T,
	issuer, clientID, redirectURI, actualLocation string,
) {
	t.Helper()

	// Do OIDC discovery on our test issuer to get auth endpoint.
	upstreamProvider, err := oidc.NewProvider(ctx, issuer)
	require.NoError(t, err)

	// Parse expected upstream auth URL.
	expectedLocationURL, err := url.Parse(
		(&oauth2.Config{
			ClientID:    clientID,
			Endpoint:    upstreamProvider.Endpoint(),
			RedirectURL: redirectURI,
		}).AuthCodeURL(""),
	)
	require.NoError(t, err)

	// Parse actual upstream auth URL.
	actualLocationURL, err := url.Parse(actualLocation)
	require.NoError(t, err)

	// First make some assertions on the query values. Note that we will not be able to know what
	// certain query values are since they may be random (e.g., state, pkce, nonce).
	expectedLocationQuery := expectedLocationURL.Query()
	actualLocationQuery := actualLocationURL.Query()
	require.NotEmpty(t, actualLocationQuery.Get("state"))
	actualLocationQuery.Del("state")
	require.NotEmpty(t, actualLocationQuery.Get("code_challenge"))
	actualLocationQuery.Del("code_challenge")
	require.NotEmpty(t, actualLocationQuery.Get("code_challenge_method"))
	actualLocationQuery.Del("code_challenge_method")
	require.NotEmpty(t, actualLocationQuery.Get("nonce"))
	actualLocationQuery.Del("nonce")
	require.Equal(t, expectedLocationQuery, actualLocationQuery)

	// Zero-out query values, since we made specific assertions about those above, and assert that the
	// URL's are equal otherwise.
	expectedLocationURL.RawQuery = ""
	actualLocationURL.RawQuery = ""
	require.Equal(t, expectedLocationURL, actualLocationURL)
}
