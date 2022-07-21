// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.pinniped.dev/internal/secret"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func TestManager(t *testing.T) {
	spec.Run(t, "ServeHTTP", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                        *require.Assertions
			subject                  *Manager
			nextHandler              http.HandlerFunc
			fallbackHandlerWasCalled bool
			dynamicJWKSProvider      jwks.DynamicJWKSProvider
			kubeClient               *fake.Clientset
		)

		const (
			issuer1                      = "https://example.com/some/path"
			issuer1DifferentCaseHostname = "https://eXamPle.coM/some/path"
			issuer1KeyID                 = "issuer1-key"
			issuer2                      = "https://example.com/some/path/more/deeply/nested/path" // note that this is a sub-path of the other issuer url
			issuer2DifferentCaseHostname = "https://exAmPlE.Com/some/path/more/deeply/nested/path"
			issuer2KeyID                 = "issuer2-key"
			upstreamIDPAuthorizationURL  = "https://test-upstream.com/auth"
			upstreamIDPName              = "test-idp"
			upstreamIDPType              = "oidc"
			downstreamClientID           = "pinniped-cli"
			downstreamRedirectURL        = "http://127.0.0.1:12345/callback"

			downstreamPKCECodeVerifier = "some-pkce-verifier-that-must-be-at-least-43-characters-to-meet-entropy-requirements"
		)

		var (
			upstreamIDPFlows = []string{"browser_authcode"}
		)

		newGetRequest := func(url string) *http.Request {
			return httptest.NewRequest(http.MethodGet, url, nil)
		}

		newPostRequest := func(url, body string) *http.Request {
			req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req
		}

		requireDiscoveryRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedIssuer string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.WellKnownEndpointPath+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			// Minimal check to ensure that the right discovery endpoint was called
			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			parsedDiscoveryResult := discovery.Metadata{}
			err = json.Unmarshal(responseBody, &parsedDiscoveryResult)
			r.NoError(err)
			r.Equal(expectedIssuer, parsedDiscoveryResult.Issuer)
			r.Equal(parsedDiscoveryResult.SupervisorDiscovery.PinnipedIDPsEndpoint, expectedIssuer+oidc.PinnipedIDPsPathV1Alpha1)
		}

		requirePinnipedIDPsDiscoveryRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedIDPName, expectedIDPType string, expectedFlows []string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.PinnipedIDPsPathV1Alpha1+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			expectedFlowsJSON, err := json.Marshal(expectedFlows)
			require.NoError(t, err)

			// Minimal check to ensure that the right IDP discovery endpoint was called
			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			r.Equal(
				fmt.Sprintf(`{"pinniped_identity_providers":[{"name":"%s","type":"%s","flows":%s}]}`+"\n", expectedIDPName, expectedIDPType, expectedFlowsJSON),
				string(responseBody),
			)
		}

		requireAuthorizationRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedRedirectLocationPrefix string) (string, string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.AuthorizationEndpointPath+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			// Minimal check to ensure that the right endpoint was called
			r.Equal(http.StatusSeeOther, recorder.Code)
			actualLocation := recorder.Header().Get("Location")
			r.True(
				strings.HasPrefix(actualLocation, expectedRedirectLocationPrefix),
				"actual location %s did not start with expected prefix %s",
				actualLocation, expectedRedirectLocationPrefix,
			)

			parsedLocation, err := url.Parse(actualLocation)
			r.NoError(err)
			redirectStateParam := parsedLocation.Query().Get("state")
			r.NotEmpty(redirectStateParam)

			cookies := recorder.Result().Cookies() //nolint:bodyclose
			r.Len(cookies, 1)
			csrfCookie := cookies[0]
			r.Equal("__Host-pinniped-csrf", csrfCookie.Name)
			r.NotEmpty(csrfCookie.Value)

			// Return the important parts of the response so we can use them in our next request to the callback endpoint
			return csrfCookie.Value, redirectStateParam
		}

		requireCallbackRequestToBeHandled := func(requestIssuer, requestURLSuffix, csrfCookieValue string) string {
			recorder := httptest.NewRecorder()

			numberOfKubeActionsBeforeThisRequest := len(kubeClient.Actions())

			getRequest := newGetRequest(requestIssuer + oidc.CallbackEndpointPath + requestURLSuffix)
			getRequest.AddCookie(&http.Cookie{
				Name:  "__Host-pinniped-csrf",
				Value: csrfCookieValue,
			})
			subject.ServeHTTP(recorder, getRequest)

			r.False(fallbackHandlerWasCalled)

			// Check just enough of the response to ensure that we wired up the callback endpoint correctly.
			// The endpoint's own unit tests cover everything else.
			r.Equal(http.StatusSeeOther, recorder.Code)
			actualLocation := recorder.Header().Get("Location")
			r.True(
				strings.HasPrefix(actualLocation, downstreamRedirectURL),
				"actual location %s did not start with expected prefix %s",
				actualLocation, downstreamRedirectURL,
			)
			parsedLocation, err := url.Parse(actualLocation)
			r.NoError(err)
			actualLocationQueryParams := parsedLocation.Query()
			r.Contains(actualLocationQueryParams, "code")
			r.Equal("openid", actualLocationQueryParams.Get("scope"))
			r.Equal("some-state-value-with-enough-bytes-to-exceed-min-allowed", actualLocationQueryParams.Get("state"))

			// Make sure that we wired up the callback endpoint to use kube storage for fosite sessions.
			r.Equal(len(kubeClient.Actions()), numberOfKubeActionsBeforeThisRequest+3,
				"did not perform any kube actions during the callback request, but should have")

			// Return the important parts of the response so we can use them in our next request to the token endpoint.
			return actualLocationQueryParams.Get("code")
		}

		requireTokenRequestToBeHandled := func(requestIssuer, authCode string, jwks *jose.JSONWebKeySet, jwkIssuer string) {
			recorder := httptest.NewRecorder()

			numberOfKubeActionsBeforeThisRequest := len(kubeClient.Actions())

			tokenRequestBody := url.Values{
				"code":          []string{authCode},
				"client_id":     []string{downstreamClientID},
				"redirect_uri":  []string{downstreamRedirectURL},
				"code_verifier": []string{downstreamPKCECodeVerifier},
				"grant_type":    []string{"authorization_code"},
			}.Encode()
			subject.ServeHTTP(recorder, newPostRequest(requestIssuer+oidc.TokenEndpointPath, tokenRequestBody))

			r.False(fallbackHandlerWasCalled)

			// Minimal check to ensure that the right endpoint was called
			var body map[string]interface{}
			r.Equal(http.StatusOK, recorder.Code)
			r.NoError(json.Unmarshal(recorder.Body.Bytes(), &body))
			r.Contains(body, "id_token")
			r.Contains(body, "access_token")

			// Validate ID token is signed by the correct JWK to make sure we wired the token endpoint
			// signing key correctly.
			idToken, ok := body["id_token"].(string)
			r.True(ok, "wanted id_token type to be string, but was %T", body["id_token"])

			r.GreaterOrEqual(len(jwks.Keys), 1)
			privateKey, ok := jwks.Keys[0].Key.(*ecdsa.PrivateKey)
			r.True(ok, "wanted private key to be *ecdsa.PrivateKey, but was %T", jwks.Keys[0].Key)

			oidctestutil.VerifyECDSAIDToken(t, jwkIssuer, downstreamClientID, privateKey, idToken)

			// Make sure that we wired up the callback endpoint to use kube storage for fosite sessions.
			r.Equal(len(kubeClient.Actions()), numberOfKubeActionsBeforeThisRequest+9,
				"did not perform any kube actions during the callback request, but should have")
		}

		requireJWKSRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedJWKKeyID string) *jose.JSONWebKeySet {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.JWKSEndpointPath+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			// Minimal check to ensure that the right JWKS endpoint was called
			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			parsedJWKSResult := jose.JSONWebKeySet{}
			err = json.Unmarshal(responseBody, &parsedJWKSResult)
			r.NoError(err)
			r.Equal(expectedJWKKeyID, parsedJWKSResult.Keys[0].KeyID)

			return &parsedJWKSResult
		}

		it.Before(func() {
			r = require.New(t)
			nextHandler = func(http.ResponseWriter, *http.Request) {
				fallbackHandlerWasCalled = true
			}
			dynamicJWKSProvider = jwks.NewDynamicJWKSProvider()

			parsedUpstreamIDPAuthorizationURL, err := url.Parse(upstreamIDPAuthorizationURL)
			r.NoError(err)
			idpLister := oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{
				Name:             upstreamIDPName,
				ClientID:         "test-client-id",
				AuthorizationURL: *parsedUpstreamIDPAuthorizationURL,
				Scopes:           []string{"test-scope"},
				ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
					return &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Claims: map[string]interface{}{
								"iss":      "https://some-issuer.com",
								"sub":      "some-subject",
								"username": "test-username",
								"groups":   "test-group1",
							},
						},
						RefreshToken: &oidctypes.RefreshToken{Token: "some-opaque-token"},
					}, nil
				},
			}).Build()

			kubeClient = fake.NewSimpleClientset()
			secretsClient := kubeClient.CoreV1().Secrets("some-namespace")

			cache := secret.Cache{}
			cache.SetCSRFCookieEncoderHashKey([]byte("fake-csrf-hash-secret"))

			cache.SetTokenHMACKey(issuer1, []byte("some secret 1 - must have at least 32 bytes"))
			cache.SetStateEncoderHashKey(issuer1, []byte("some-state-encoder-hash-key-1"))
			cache.SetStateEncoderBlockKey(issuer1, []byte("16-bytes-STATE01"))

			cache.SetTokenHMACKey(issuer2, []byte("some secret 2 - must have at least 32 bytes"))
			cache.SetStateEncoderHashKey(issuer2, []byte("some-state-encoder-hash-key-2"))
			cache.SetStateEncoderBlockKey(issuer2, []byte("16-bytes-STATE02"))

			subject = NewManager(nextHandler, dynamicJWKSProvider, idpLister, &cache, secretsClient)
		})

		when("given no providers via SetProviders()", func() {
			it("sends all requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest("/anything"))
				r.True(fallbackHandlerWasCalled)
			})
		})

		newTestJWK := func(keyID string) *jose.JSONWebKey {
			testJWKSJSONString := here.Docf(`
				{
				  "use": "sig",
				  "kty": "EC",
				  "kid": "%s",
				  "crv": "P-256",
				  "alg": "ES256",
				  "x": "9c_oMKjd_ruVIy4pA5y9quT1E-Fampx0w270OtPx5Ng",
				  "y": "-Y-9nfrtJdFPl-9kzXv55-Fq9Oo2AWDg5zZBs9P-Vds",
				  "d": "LXdNChAEtGKETBzYXiL_G0wESXceBuajE_EBQbcRuGg"
				}
			`, keyID)
			k := jose.JSONWebKey{}
			r.NoError(json.Unmarshal([]byte(testJWKSJSONString), &k))
			return &k
		}

		requireRoutesMatchingRequestsToAppropriateProvider := func() {
			requireDiscoveryRequestToBeHandled(issuer1, "", issuer1)
			requireDiscoveryRequestToBeHandled(issuer2, "", issuer2)
			requireDiscoveryRequestToBeHandled(issuer2, "?some=query", issuer2)

			// Hostnames are case-insensitive, so test that we can handle that.
			requireDiscoveryRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1)
			requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2)
			requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2)

			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer1, "", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)
			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer2, "", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)
			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer2, "?some=query", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)

			// Hostnames are case-insensitive, so test that we can handle that.
			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer1DifferentCaseHostname, "", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)
			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)
			requirePinnipedIDPsDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", upstreamIDPName, upstreamIDPType, upstreamIDPFlows)

			issuer1JWKS := requireJWKSRequestToBeHandled(issuer1, "", issuer1KeyID)
			issuer2JWKS := requireJWKSRequestToBeHandled(issuer2, "", issuer2KeyID)
			requireJWKSRequestToBeHandled(issuer2, "?some=query", issuer2KeyID)

			// Hostnames are case-insensitive, so test that we can handle that.
			requireJWKSRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1KeyID)
			requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2KeyID)
			requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2KeyID)

			authRequestParams := "?" + url.Values{
				"response_type":         []string{"code"},
				"scope":                 []string{"openid profile email"},
				"client_id":             []string{downstreamClientID},
				"state":                 []string{"some-state-value-with-enough-bytes-to-exceed-min-allowed"},
				"nonce":                 []string{"some-nonce-value-with-enough-bytes-to-exceed-min-allowed"},
				"code_challenge":        []string{testutil.SHA256(downstreamPKCECodeVerifier)},
				"code_challenge_method": []string{"S256"},
				"redirect_uri":          []string{downstreamRedirectURL},
			}.Encode()

			requireAuthorizationRequestToBeHandled(issuer1, authRequestParams, upstreamIDPAuthorizationURL)
			requireAuthorizationRequestToBeHandled(issuer2, authRequestParams, upstreamIDPAuthorizationURL)

			// Hostnames are case-insensitive, so test that we can handle that.
			csrfCookieValue1, upstreamStateParam1 :=
				requireAuthorizationRequestToBeHandled(issuer1DifferentCaseHostname, authRequestParams, upstreamIDPAuthorizationURL)
			csrfCookieValue2, upstreamStateParam2 :=
				requireAuthorizationRequestToBeHandled(issuer2DifferentCaseHostname, authRequestParams, upstreamIDPAuthorizationURL)

			callbackRequestParams1 := "?" + url.Values{
				"code":  []string{"some-fake-code"},
				"state": []string{upstreamStateParam1},
			}.Encode()
			callbackRequestParams2 := "?" + url.Values{
				"code":  []string{"some-fake-code"},
				"state": []string{upstreamStateParam2},
			}.Encode()

			downstreamAuthCode1 := requireCallbackRequestToBeHandled(issuer1, callbackRequestParams1, csrfCookieValue1)
			downstreamAuthCode2 := requireCallbackRequestToBeHandled(issuer2, callbackRequestParams2, csrfCookieValue2)

			// Hostnames are case-insensitive, so test that we can handle that.
			downstreamAuthCode3 := requireCallbackRequestToBeHandled(issuer1DifferentCaseHostname, callbackRequestParams1, csrfCookieValue1)
			downstreamAuthCode4 := requireCallbackRequestToBeHandled(issuer2DifferentCaseHostname, callbackRequestParams2, csrfCookieValue2)

			requireTokenRequestToBeHandled(issuer1, downstreamAuthCode1, issuer1JWKS, issuer1)
			requireTokenRequestToBeHandled(issuer2, downstreamAuthCode2, issuer2JWKS, issuer2)

			// Hostnames are case-insensitive, so test that we can handle that.
			requireTokenRequestToBeHandled(issuer1DifferentCaseHostname, downstreamAuthCode3, issuer1JWKS, issuer1)
			requireTokenRequestToBeHandled(issuer2DifferentCaseHostname, downstreamAuthCode4, issuer2JWKS, issuer2)
		}

		when("given some valid providers via SetProviders()", func() {
			it.Before(func() {
				p1, err := provider.NewFederationDomainIssuer(issuer1)
				r.NoError(err)
				p2, err := provider.NewFederationDomainIssuer(issuer2)
				r.NoError(err)
				subject.SetProviders(p1, p2)

				jwksMap := map[string]*jose.JSONWebKeySet{
					issuer1: {Keys: []jose.JSONWebKey{*newTestJWK(issuer1KeyID)}},
					issuer2: {Keys: []jose.JSONWebKey{*newTestJWK(issuer2KeyID)}},
				}
				activeJWK := map[string]*jose.JSONWebKey{
					issuer1: newTestJWK(issuer1KeyID),
					issuer2: newTestJWK(issuer2KeyID),
				}
				dynamicJWKSProvider.SetIssuerToJWKSMap(jwksMap, activeJWK)
			})

			it("sends all non-matching host requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				wrongHostURL := strings.ReplaceAll(issuer1+oidc.WellKnownEndpointPath, "example.com", "wrong-host.com")
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest(wrongHostURL))
				r.True(fallbackHandlerWasCalled)
			})

			it("sends all non-matching path requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest("https://example.com/path-does-not-match-any-provider"))
				r.True(fallbackHandlerWasCalled)
			})

			it("sends requests which match the issuer prefix but do not match any of that provider's known paths to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest(issuer1+"/unhandled-sub-path"))
				r.True(fallbackHandlerWasCalled)
			})

			it("routes matching requests to the appropriate provider", func() {
				requireRoutesMatchingRequestsToAppropriateProvider()
			})
		})

		when("given the same valid providers as arguments to SetProviders() in reverse order", func() {
			it.Before(func() {
				p1, err := provider.NewFederationDomainIssuer(issuer1)
				r.NoError(err)
				p2, err := provider.NewFederationDomainIssuer(issuer2)
				r.NoError(err)
				subject.SetProviders(p2, p1)

				jwksMap := map[string]*jose.JSONWebKeySet{
					issuer1: {Keys: []jose.JSONWebKey{*newTestJWK(issuer1KeyID)}},
					issuer2: {Keys: []jose.JSONWebKey{*newTestJWK(issuer2KeyID)}},
				}
				activeJWK := map[string]*jose.JSONWebKey{
					issuer1: newTestJWK(issuer1KeyID),
					issuer2: newTestJWK(issuer2KeyID),
				}
				dynamicJWKSProvider.SetIssuerToJWKSMap(jwksMap, activeJWK)
			})

			it("still routes matching requests to the appropriate provider", func() {
				requireRoutesMatchingRequestsToAppropriateProvider()
			})
		})
	})
}
