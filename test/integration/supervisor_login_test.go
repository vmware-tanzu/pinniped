// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
	"go.pinniped.dev/test/library"
	"go.pinniped.dev/test/library/browsertest"
)

func TestSupervisorLogin(t *testing.T) {
	env := library.IntegrationEnv(t)

	// If anything in this test crashes, dump out the supervisor and proxy pod logs.
	defer library.DumpLogs(t, env.SupervisorNamespace, "")
	defer library.DumpLogs(t, "dex", "app=proxy")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Infer the downstream issuer URL from the callback associated with the upstream test client registration.
	issuerURL, err := url.Parse(env.SupervisorTestUpstream.CallbackURL)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(issuerURL.Path, "/callback"))
	issuerURL.Path = strings.TrimSuffix(issuerURL.Path, "/callback")
	t.Logf("testing with downstream issuer URL %s", issuerURL.String())

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	ca, err := certauthority.New(pkix.Name{CommonName: "Downstream Test CA"}, 1*time.Hour)
	require.NoError(t, err)

	// Create an HTTP client that can reach the downstream discovery endpoint using the CA certs.
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
		Proxy: func(req *http.Request) (*url.URL, error) {
			if env.Proxy == "" {
				t.Logf("passing request for %s with no proxy", req.URL)
				return nil, nil
			}
			proxyURL, err := url.Parse(env.Proxy)
			require.NoError(t, err)
			t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
			return proxyURL, nil
		},
	}}
	oidcHTTPClientContext := coreosoidc.ClientContext(ctx, httpClient)

	// Use the CA to issue a TLS server cert.
	t.Logf("issuing test certificate")
	tlsCert, err := ca.Issue(
		pkix.Name{CommonName: issuerURL.Hostname()},
		[]string{issuerURL.Hostname()},
		nil,
		1*time.Hour,
	)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)

	// Write the serving cert to a secret.
	certSecret := library.CreateTestSecret(t,
		env.SupervisorNamespace,
		"oidc-provider-tls",
		"kubernetes.io/tls",
		map[string]string{"tls.crt": string(certPEM), "tls.key": string(keyPEM)},
	)

	// Create the downstream OIDCProvider and expect it to go into the success status condition.
	downstream := library.CreateTestOIDCProvider(ctx, t,
		issuerURL.String(),
		certSecret.Name,
		configv1alpha1.SuccessOIDCProviderStatusCondition,
	)

	// Create upstream OIDC provider and wait for it to become ready.
	library.CreateTestUpstreamOIDCProvider(t, idpv1alpha1.UpstreamOIDCProviderSpec{
		Issuer: env.SupervisorTestUpstream.Issuer,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorTestUpstream.CABundle)),
		},
		Client: idpv1alpha1.OIDCClient{
			SecretName: library.CreateClientCredsSecret(t, env.SupervisorTestUpstream.ClientID, env.SupervisorTestUpstream.ClientSecret).Name,
		},
	}, idpv1alpha1.PhaseReady)

	// Perform OIDC discovery for our downstream.
	var discovery *coreosoidc.Provider
	assert.Eventually(t, func() bool {
		discovery, err = coreosoidc.NewProvider(oidcHTTPClientContext, downstream.Spec.Issuer)
		return err == nil
	}, 30*time.Second, 200*time.Millisecond)
	require.NoError(t, err)

	// Start a callback server on localhost.
	localCallbackServer := startLocalCallbackServer(t)

	// Form the OAuth2 configuration corresponding to our CLI client.
	downstreamOAuth2Config := oauth2.Config{
		// This is the hardcoded public client that the supervisor supports.
		ClientID:    "pinniped-cli",
		Endpoint:    discovery.Endpoint(),
		RedirectURL: localCallbackServer.URL,
		Scopes:      []string{"openid", "pinniped.sts.unrestricted", "offline_access"},
	}

	// Build a valid downstream authorize URL for the supervisor.
	stateParam, err := state.Generate()
	require.NoError(t, err)
	nonceParam, err := nonce.Generate()
	require.NoError(t, err)
	pkceParam, err := pkce.Generate()
	require.NoError(t, err)
	downstreamAuthorizeURL := downstreamOAuth2Config.AuthCodeURL(
		stateParam.String(),
		nonceParam.Param(),
		pkceParam.Challenge(),
		pkceParam.Method(),
	)

	// Open the web browser and navigate to the downstream authorize URL.
	page := browsertest.Open(t)
	t.Logf("opening browser to downstream authorize URL %s", library.MaskTokens(downstreamAuthorizeURL))
	require.NoError(t, page.Navigate(downstreamAuthorizeURL))

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstream(t, page, env.SupervisorTestUpstream)

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(localCallbackServer.URL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)

	// Expect that our callback handler was invoked.
	callback := localCallbackServer.waitForCallback(10 * time.Second)
	t.Logf("got callback request: %s", library.MaskTokens(callback.URL.String()))
	require.Equal(t, stateParam.String(), callback.URL.Query().Get("state"))
	require.ElementsMatch(t, []string{"openid", "pinniped.sts.unrestricted", "offline_access"}, strings.Split(callback.URL.Query().Get("scope"), " "))
	authcode := callback.URL.Query().Get("code")
	require.NotEmpty(t, authcode)

	// Call the token endpoint to get tokens. Give the Supervisor a couple of seconds to wire up its signing key.
	var tokenResponse *oauth2.Token
	assert.Eventually(t, func() bool {
		tokenResponse, err = downstreamOAuth2Config.Exchange(oidcHTTPClientContext, authcode, pkceParam.Verifier())
		if err != nil {
			t.Logf("error trying to exchange auth code (%s), trying again", err.Error())
		}
		return err == nil
	}, time.Second*5, time.Second*1)
	require.NoError(t, err)

	expectedIDTokenClaims := []string{"iss", "exp", "sub", "aud", "auth_time", "iat", "jti", "nonce", "rat"}
	verifyTokenResponse(t, tokenResponse, discovery, downstreamOAuth2Config, env.SupervisorTestUpstream.Issuer, nonceParam, expectedIDTokenClaims)

	// token exchange on the original token
	doTokenExchange(t, &downstreamOAuth2Config, tokenResponse, httpClient, discovery)

	// Use the refresh token to get new tokens
	refreshSource := downstreamOAuth2Config.TokenSource(oidcHTTPClientContext, &oauth2.Token{RefreshToken: tokenResponse.RefreshToken})
	refreshedTokenResponse, err := refreshSource.Token()
	require.NoError(t, err)

	expectedIDTokenClaims = append(expectedIDTokenClaims, "at_hash")
	verifyTokenResponse(t, refreshedTokenResponse, discovery, downstreamOAuth2Config, env.SupervisorTestUpstream.Issuer, "", expectedIDTokenClaims)

	require.NotEqual(t, tokenResponse.AccessToken, refreshedTokenResponse.AccessToken)
	require.NotEqual(t, tokenResponse.RefreshToken, refreshedTokenResponse.RefreshToken)
	require.NotEqual(t, tokenResponse.Extra("id_token"), refreshedTokenResponse.Extra("id_token"))

	// token exchange on the refreshed token
	doTokenExchange(t, &downstreamOAuth2Config, refreshedTokenResponse, httpClient, discovery)
}

func verifyTokenResponse(
	t *testing.T,
	tokenResponse *oauth2.Token,
	discovery *coreosoidc.Provider,
	downstreamOAuth2Config oauth2.Config,
	upstreamIssuerName string,
	nonceParam nonce.Nonce,
	expectedIDTokenClaims []string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Verify the ID Token.
	rawIDToken, ok := tokenResponse.Extra("id_token").(string)
	require.True(t, ok, "expected to get an ID token but did not")
	var verifier = discovery.Verifier(&coreosoidc.Config{ClientID: downstreamOAuth2Config.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	require.NoError(t, err)

	// Check the claims of the ID token.
	expectedSubjectPrefix := upstreamIssuerName + "?sub="
	require.True(t, strings.HasPrefix(idToken.Subject, expectedSubjectPrefix))
	require.Greater(t, len(idToken.Subject), len(expectedSubjectPrefix),
		"the ID token Subject should include the upstream user ID after the upstream issuer name")
	require.NoError(t, nonceParam.Validate(idToken))
	expectedIDTokenLifetime := oidc.DefaultOIDCTimeoutsConfiguration().IDTokenLifespan
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(expectedIDTokenLifetime), idToken.Expiry, time.Second*30)
	idTokenClaims := map[string]interface{}{}
	err = idToken.Claims(&idTokenClaims)
	require.NoError(t, err)
	idTokenClaimNames := []string{}
	for k := range idTokenClaims {
		idTokenClaimNames = append(idTokenClaimNames, k)
	}
	require.ElementsMatch(t, expectedIDTokenClaims, idTokenClaimNames)

	// Some light verification of the other tokens that were returned.
	require.NotEmpty(t, tokenResponse.AccessToken)
	require.Equal(t, "bearer", tokenResponse.TokenType)
	require.NotZero(t, tokenResponse.Expiry)
	expectedAccessTokenLifetime := oidc.DefaultOIDCTimeoutsConfiguration().AccessTokenLifespan
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(expectedAccessTokenLifetime), tokenResponse.Expiry, time.Second*30)

	require.NotEmpty(t, tokenResponse.RefreshToken)
}

func startLocalCallbackServer(t *testing.T) *localCallbackServer {
	// Handle the callback by sending the *http.Request object back through a channel.
	callbacks := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks <- r
	}))
	server.URL += "/callback"
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(callbacks) })
	return &localCallbackServer{Server: server, t: t, callbacks: callbacks}
}

type localCallbackServer struct {
	*httptest.Server
	t         *testing.T
	callbacks <-chan *http.Request
}

func (s *localCallbackServer) waitForCallback(timeout time.Duration) *http.Request {
	select {
	case callback := <-s.callbacks:
		return callback
	case <-time.After(timeout):
		require.Fail(s.t, "timed out waiting for callback request")
		return nil
	}
}

func doTokenExchange(t *testing.T, config *oauth2.Config, tokenResponse *oauth2.Token, httpClient *http.Client, provider *coreosoidc.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"grant_type":           []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             []string{"cluster-1234"},
		"client_id":            []string{config.ClientID},
		"subject_token":        []string{tokenResponse.AccessToken},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.TokenURL, reqBody)
	require.NoError(t, err)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var respBody struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	var clusterVerifier = provider.Verifier(&coreosoidc.Config{ClientID: "cluster-1234"})
	exchangedToken, err := clusterVerifier.Verify(ctx, respBody.AccessToken)
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, exchangedToken.Claims(&claims))
	indentedClaims, err := json.MarshalIndent(claims, "   ", "  ")
	require.NoError(t, err)
	t.Logf("exchanged token claims:\n%s", string(indentedClaims))
}
