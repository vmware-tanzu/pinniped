/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/suzerain-io/placeholder-name/internal/testutil"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/placeholder-name/pkg/client"
)

func TestRun(t *testing.T) {
	spec.Run(t, "main.run", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var buffer *bytes.Buffer
		var tokenExchanger tokenExchanger
		var fakeEnv map[string]string

		var envGetter envGetter = func(envVarName string) (string, bool) {
			value, present := fakeEnv[envVarName]
			if !present {
				return "", false
			}
			return value, true
		}

		it.Before(func() {
			r = require.New(t)
			buffer = new(bytes.Buffer)
			fakeEnv = map[string]string{
				"PLACEHOLDER_NAME_TOKEN":            "token from env",
				"PLACEHOLDER_NAME_CA_BUNDLE":        "ca bundle from env",
				"PLACEHOLDER_NAME_K8S_API_ENDPOINT": "k8s api from env",
			}
		})

		when("env vars are missing", func() {
			it("returns an error when PLACEHOLDER_NAME_TOKEN is missing", func() {
				delete(fakeEnv, "PLACEHOLDER_NAME_TOKEN")
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to login: environment variable not set: PLACEHOLDER_NAME_TOKEN")
			})

			it("returns an error when PLACEHOLDER_NAME_CA_BUNDLE is missing", func() {
				delete(fakeEnv, "PLACEHOLDER_NAME_CA_BUNDLE")
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to login: environment variable not set: PLACEHOLDER_NAME_CA_BUNDLE")
			})

			it("returns an error when PLACEHOLDER_NAME_K8S_API_ENDPOINT is missing", func() {
				delete(fakeEnv, "PLACEHOLDER_NAME_K8S_API_ENDPOINT")
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to login: environment variable not set: PLACEHOLDER_NAME_K8S_API_ENDPOINT")
			})
		})

		when("the token exchange fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*client.Credential, error) {
					return nil, fmt.Errorf("some error")
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to login: some error")
			})
		})

		when("the JSON encoder fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*client.Credential, error) {
					return &client.Credential{Token: "some token"}, nil
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, &testutil.ErrorWriter{ReturnError: fmt.Errorf("some IO error")}, 30*time.Second)
				r.EqualError(err, "failed to marshal response to stdout: some IO error")
			})
		})

		when("the token exchange times out", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*client.Credential, error) {
					select {
					case <-time.After(100 * time.Millisecond):
						return &client.Credential{Token: "some token"}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, buffer, 1*time.Millisecond)
				r.EqualError(err, "failed to login: context deadline exceeded")
			})
		})

		when("the token exchange succeeds", func() {
			var actualToken, actualCaBundle, actualAPIEndpoint string

			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*client.Credential, error) {
					actualToken, actualCaBundle, actualAPIEndpoint = token, caBundle, apiEndpoint
					now := time.Date(2020, 7, 29, 1, 2, 3, 0, time.UTC)
					return &client.Credential{
						ExpirationTimestamp:   &now,
						ClientCertificateData: "some certificate",
						ClientKeyData:         "some key",
						Token:                 "some token",
					}, nil
				}
			})

			it("writes the execCredential to the given writer", func() {
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.NoError(err)
				r.Equal(fakeEnv["PLACEHOLDER_NAME_TOKEN"], actualToken)
				r.Equal(fakeEnv["PLACEHOLDER_NAME_CA_BUNDLE"], actualCaBundle)
				r.Equal(fakeEnv["PLACEHOLDER_NAME_K8S_API_ENDPOINT"], actualAPIEndpoint)
				expected := `{
				  "kind": "ExecCredential",
				  "apiVersion": "client.authentication.k8s.io/v1beta1",
				  "spec": {},
				  "status": {
					"expirationTimestamp":"2020-07-29T01:02:03Z",
					"clientCertificateData": "some certificate",
					"clientKeyData":"some key",
					"token": "some token"
				  }
				}`
				r.JSONEq(expected, buffer.String())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
