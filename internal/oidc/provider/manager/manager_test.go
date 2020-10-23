// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
)

func TestManager(t *testing.T) {
	spec.Run(t, "ServeHTTP", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                        *require.Assertions
			subject                  *Manager
			nextHandler              http.HandlerFunc
			fallbackHandlerWasCalled bool
			dynamicJWKSProvider      jwks.DynamicJWKSProvider
		)

		issuer1 := "https://example.com/some/path"
		issuer1DifferentCaseHostname := "https://eXamPle.coM/some/path"
		issuer1KeyID := "issuer1-key"
		issuer2 := "https://example.com/some/path/more/deeply/nested/path" // note that this is a sub-path of the other issuer url
		issuer2DifferentCaseHostname := "https://exAmPlE.Com/some/path/more/deeply/nested/path"
		issuer2KeyID := "issuer2-key"

		newGetRequest := func(url string) *http.Request {
			return httptest.NewRequest(http.MethodGet, url, nil)
		}

		requireDiscoveryRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedIssuerInResponse string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.WellKnownEndpointPath+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			parsedDiscoveryResult := discovery.Metadata{}
			err = json.Unmarshal(responseBody, &parsedDiscoveryResult)
			r.NoError(err)

			// Minimal check to ensure that the right discovery endpoint was called
			r.Equal(expectedIssuerInResponse, parsedDiscoveryResult.Issuer)
		}

		requireJWKSRequestToBeHandled := func(requestIssuer, requestURLSuffix, expectedJWKKeyID string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(requestIssuer+oidc.JWKSEndpointPath+requestURLSuffix))

			r.False(fallbackHandlerWasCalled)

			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			parsedJWKSResult := jose.JSONWebKeySet{}
			err = json.Unmarshal(responseBody, &parsedJWKSResult)
			r.NoError(err)

			// Minimal check to ensure that the right JWKS endpoint was called
			r.Equal(expectedJWKKeyID, parsedJWKSResult.Keys[0].KeyID)
		}

		it.Before(func() {
			r = require.New(t)
			nextHandler = func(http.ResponseWriter, *http.Request) {
				fallbackHandlerWasCalled = true
			}
			dynamicJWKSProvider = jwks.NewDynamicJWKSProvider()
			subject = NewManager(nextHandler, dynamicJWKSProvider)
		})

		when("given no providers via SetProviders()", func() {
			it("sends all requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest("/anything"))
				r.True(fallbackHandlerWasCalled)
			})
		})

		newTestJWK := func(keyID string) jose.JSONWebKey {
			testJWKSJSONString := here.Docf(`
				{
				  "use": "sig",
				  "kty": "EC",
				  "kid": "%s",
				  "crv": "P-256",
				  "alg": "ES256",
				  "x": "awmmj6CIMhSoJyfsqH7sekbTeY72GGPLEy16tPWVz2U",
				  "y": "FcMh06uXLaq9b2MOixlLVidUkycO1u7IHOkrTi7N0aw"
				}
			`, keyID)
			k := jose.JSONWebKey{}
			r.NoError(json.Unmarshal([]byte(testJWKSJSONString), &k))
			return k
		}

		when("given some valid providers via SetProviders()", func() {
			it.Before(func() {
				p1, err := provider.NewOIDCProvider(issuer1)
				r.NoError(err)
				p2, err := provider.NewOIDCProvider(issuer2)
				r.NoError(err)
				subject.SetProviders(p1, p2)

				dynamicJWKSProvider.SetIssuerToJWKSMap(map[string]*jose.JSONWebKeySet{
					issuer1: {Keys: []jose.JSONWebKey{newTestJWK(issuer1KeyID)}},
					issuer2: {Keys: []jose.JSONWebKey{newTestJWK(issuer2KeyID)}},
				})
			})

			it("sends all non-matching host requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				url := strings.ReplaceAll(issuer1+oidc.WellKnownEndpointPath, "example.com", "wrong-host.com")
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest(url))
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
				requireDiscoveryRequestToBeHandled(issuer1, "", issuer1)
				requireDiscoveryRequestToBeHandled(issuer2, "", issuer2)
				requireDiscoveryRequestToBeHandled(issuer2, "?some=query", issuer2)

				// Hostnames are case-insensitive, so test that we can handle that.
				requireDiscoveryRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1)
				requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2)
				requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2)

				requireJWKSRequestToBeHandled(issuer1, "", issuer1KeyID)
				requireJWKSRequestToBeHandled(issuer2, "", issuer2KeyID)
				requireJWKSRequestToBeHandled(issuer2, "?some=query", issuer2KeyID)

				// Hostnames are case-insensitive, so test that we can handle that.
				requireJWKSRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1KeyID)
				requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2KeyID)
				requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2KeyID)
			})
		})

		when("given the same valid providers as arguments to SetProviders() in reverse order", func() {
			it.Before(func() {
				p1, err := provider.NewOIDCProvider(issuer1)
				r.NoError(err)
				p2, err := provider.NewOIDCProvider(issuer2)
				r.NoError(err)
				subject.SetProviders(p2, p1)

				dynamicJWKSProvider.SetIssuerToJWKSMap(map[string]*jose.JSONWebKeySet{
					issuer1: {Keys: []jose.JSONWebKey{newTestJWK(issuer1KeyID)}},
					issuer2: {Keys: []jose.JSONWebKey{newTestJWK(issuer2KeyID)}},
				})
			})

			it("still routes matching requests to the appropriate provider", func() {
				requireDiscoveryRequestToBeHandled(issuer1, "", issuer1)
				requireDiscoveryRequestToBeHandled(issuer2, "", issuer2)
				requireDiscoveryRequestToBeHandled(issuer2, "?some=query", issuer2)

				// Hostnames are case-insensitive, so test that we can handle that.
				requireDiscoveryRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1)
				requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2)
				requireDiscoveryRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2)

				requireJWKSRequestToBeHandled(issuer1, "", issuer1KeyID)
				requireJWKSRequestToBeHandled(issuer2, "", issuer2KeyID)
				requireJWKSRequestToBeHandled(issuer2, "?some=query", issuer2KeyID)

				// Hostnames are case-insensitive, so test that we can handle that.
				requireJWKSRequestToBeHandled(issuer1DifferentCaseHostname, "", issuer1KeyID)
				requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "", issuer2KeyID)
				requireJWKSRequestToBeHandled(issuer2DifferentCaseHostname, "?some=query", issuer2KeyID)
			})
		})
	})
}
