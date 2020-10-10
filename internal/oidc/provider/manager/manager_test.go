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

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/provider"
)

func TestManager(t *testing.T) {
	spec.Run(t, "ServeHTTP", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var subject *Manager
		var nextHandler http.HandlerFunc
		var fallbackHandlerWasCalled bool

		newGetRequest := func(url string) *http.Request {
			return httptest.NewRequest(http.MethodGet, url, nil)
		}

		requireDiscoveryRequestToBeHandled := func(issuer, requestURLSuffix string) {
			recorder := httptest.NewRecorder()

			subject.ServeHTTP(recorder, newGetRequest(issuer+oidc.WellKnownEndpointPath+requestURLSuffix))

			r.Equal(http.StatusOK, recorder.Code)
			responseBody, err := ioutil.ReadAll(recorder.Body)
			r.NoError(err)
			parsedDiscoveryResult := discovery.Metadata{}
			err = json.Unmarshal(responseBody, &parsedDiscoveryResult)
			r.NoError(err)

			r.Equal(issuer, parsedDiscoveryResult.Issuer)
		}

		it.Before(func() {
			r = require.New(t)
			nextHandler = func(http.ResponseWriter, *http.Request) {
				fallbackHandlerWasCalled = true
			}
			subject = NewManager(nextHandler)
		})

		when("given no providers", func() {
			it("sends all requests to the nextHandler", func() {
				r.False(fallbackHandlerWasCalled)
				subject.ServeHTTP(httptest.NewRecorder(), newGetRequest("/anything"))
				r.True(fallbackHandlerWasCalled)
			})
		})

		when("given some valid providers", func() {
			issuer1 := "https://example.com/some/path"
			issuer2 := "https://example.com/some/path/more/deeply/nested/path" // note that this is a sub-path of the other issuer url

			it.Before(func() {
				p1, err := provider.NewOIDCProvider(issuer1)
				r.NoError(err)
				p2, err := provider.NewOIDCProvider(issuer2)
				r.NoError(err)
				subject.SetProviders(p1, p2)
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
				requireDiscoveryRequestToBeHandled(issuer1, "")
				requireDiscoveryRequestToBeHandled(issuer2, "")
				requireDiscoveryRequestToBeHandled(issuer2, "?some=query")
				r.False(fallbackHandlerWasCalled)
			})
		})

		when("given the same valid providers in reverse order", func() {
			issuer1 := "https://example.com/some/path"
			issuer2 := "https://example.com/some/path/more/deeply/nested/path"

			it.Before(func() {
				p1, err := provider.NewOIDCProvider(issuer1)
				r.NoError(err)
				p2, err := provider.NewOIDCProvider(issuer2)
				r.NoError(err)
				subject.SetProviders(p2, p1)
			})

			it("still routes matching requests to the appropriate provider", func() {
				requireDiscoveryRequestToBeHandled(issuer1, "")
				requireDiscoveryRequestToBeHandled(issuer2, "")
				requireDiscoveryRequestToBeHandled(issuer2, "?some=query")
				r.False(fallbackHandlerWasCalled)
			})
		})
	})
}
