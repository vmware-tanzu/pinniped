// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"go.pinniped.dev/test/library"
)

func TestSupervisorLogin(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tests := []struct {
		Scheme   string
		Address  string
		CABundle string
	}{
		{Scheme: "http", Address: env.SupervisorHTTPAddress},
		{Scheme: "https", Address: env.SupervisorHTTPSIngressAddress, CABundle: env.SupervisorHTTPSIngressCABundle},
	}

	for _, test := range tests {
		scheme := test.Scheme
		addr := test.Address
		caBundle := test.CABundle

		if addr == "" {
			// Both cases are not required, so when one is empty skip it.
			continue
		}

		// Create downstream OIDC provider (i.e., update supervisor with OIDC provider).
		path := getDownstreamIssuerPathFromUpstreamRedirectURI(t, env.SupervisorTestUpstream.CallbackURL)
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
		spec := idpv1alpha1.UpstreamOIDCProviderSpec{
			Issuer: env.SupervisorTestUpstream.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorTestUpstream.CABundle)),
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: makeTestClientCredsSecret(t, env.SupervisorTestUpstream.ClientID, env.SupervisorTestUpstream.ClientSecret).Name,
			},
		}
		upstream := makeTestUpstream(t, spec, idpv1alpha1.PhaseReady)

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
			upstream.Spec.Issuer,
			env.SupervisorTestUpstream.ClientID,
			env.SupervisorTestUpstream.CallbackURL,
			rsp.Header.Get("Location"),
		)
	}
}

func getDownstreamIssuerPathFromUpstreamRedirectURI(t *testing.T, upstreamRedirectURI string) string {
	// We need to construct the downstream issuer path from the upstream redirect URI since the two
	// are related, and the upstream redirect URI is supplied via a static test environment
	// variable. The upstream redirect URI should be something like
	//   https://supervisor.com/some/supervisor/path/callback
	// and therefore the downstream issuer should be something like
	//   https://supervisor.com/some/supervisor/path
	// since the /callback endpoint is placed at the root of the downstream issuer path.
	upstreamRedirectURL, err := url.Parse(upstreamRedirectURI)
	require.NoError(t, err)

	redirectURIPathWithoutLastSegment, lastUpstreamRedirectURIPathSegment := path.Split(upstreamRedirectURL.Path)
	require.Equalf(
		t,
		"callback",
		lastUpstreamRedirectURIPathSegment,
		"expected upstream redirect URI (%q) to follow supervisor callback path conventions (i.e., end in /callback)",
		upstreamRedirectURI,
	)

	if strings.HasSuffix(redirectURIPathWithoutLastSegment, "/") {
		redirectURIPathWithoutLastSegment = redirectURIPathWithoutLastSegment[:len(redirectURIPathWithoutLastSegment)-1]
	}

	return redirectURIPathWithoutLastSegment
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
	env := library.IntegrationEnv(t)

	// Do OIDC discovery on our test issuer to get auth endpoint.
	transport := http.Transport{}
	if env.Proxy != "" {
		transport.Proxy = func(_ *http.Request) (*url.URL, error) {
			return url.Parse(env.Proxy)
		}
	}
	if env.SupervisorTestUpstream.CABundle != "" {
		transport.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
		transport.TLSClientConfig.RootCAs.AppendCertsFromPEM([]byte(env.SupervisorTestUpstream.CABundle))
	}

	ctx = oidc.ClientContext(ctx, &http.Client{Transport: &transport})
	upstreamProvider, err := oidc.NewProvider(ctx, issuer)
	require.NoError(t, err)

	// Parse expected upstream auth URL.
	expectedLocationURL, err := url.Parse(
		(&oauth2.Config{
			ClientID:    clientID,
			Endpoint:    upstreamProvider.Endpoint(),
			RedirectURL: redirectURI,
			Scopes:      []string{"openid"},
		}).AuthCodeURL("", oauth2.AccessTypeOffline),
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
