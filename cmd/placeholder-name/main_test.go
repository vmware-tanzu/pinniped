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

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/pkg/apis/clientauthentication"

	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestRun(t *testing.T) {
	spec.Run(t, "Run", func(t *testing.T, when spec.G, it spec.S) {
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
			buffer = new(bytes.Buffer)
			fakeEnv = map[string]string{
				"PLACEHOLDER_NAME_TOKEN":            "token from env",
				"PLACEHOLDER_NAME_CA_BUNDLE":        "ca bundle from env",
				"PLACEHOLDER_NAME_K8S_API_ENDPOINT": "k8s api from env",
			}
		})

		when("env vars are missing", func() {
			it("returns an error when PLACEHOLDER_NAME_TOKEN is missing", func() {
				fakeEnv = map[string]string{
					"PLACEHOLDER_NAME_K8S_API_ENDPOINT": "a",
					"PLACEHOLDER_NAME_CA_BUNDLE":        "b",
				}
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				require.EqualError(t, err, "failed to login: environment variable not set: PLACEHOLDER_NAME_TOKEN")
			})

			it("returns an error when PLACEHOLDER_NAME_CA_BUNDLE is missing", func() {
				fakeEnv = map[string]string{
					"PLACEHOLDER_NAME_K8S_API_ENDPOINT": "a",
					"PLACEHOLDER_NAME_TOKEN":            "b",
				}
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				require.EqualError(t, err, "failed to login: environment variable not set: PLACEHOLDER_NAME_CA_BUNDLE")
			})

			it("returns an error when PLACEHOLDER_NAME_K8S_API_ENDPOINT is missing", func() {
				fakeEnv = map[string]string{
					"PLACEHOLDER_NAME_TOKEN":     "a",
					"PLACEHOLDER_NAME_CA_BUNDLE": "b",
				}
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				require.EqualError(t, err, "failed to login: environment variable not set: PLACEHOLDER_NAME_K8S_API_ENDPOINT")
			})
		}, spec.Parallel())

		when("the token exchange fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
					return nil, fmt.Errorf("some error")
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				require.EqualError(t, err, "failed to login: some error")
			})
		}, spec.Parallel())

		when("the JSON encoder fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
					return &clientauthentication.ExecCredential{
						Status: &clientauthentication.ExecCredentialStatus{Token: "some token"},
					}, nil
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, &library.ErrorWriter{ReturnError: fmt.Errorf("some IO error")}, 30*time.Second)
				require.EqualError(t, err, "failed to marshal response to stdout: some IO error")
			})
		}, spec.Parallel())

		when("the token exchange times out", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
					select {
					case <-time.After(100 * time.Millisecond):
						return &clientauthentication.ExecCredential{
							Status: &clientauthentication.ExecCredentialStatus{Token: "some token"},
						}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, buffer, 1*time.Millisecond)
				require.EqualError(t, err, "failed to login: context deadline exceeded")
			})
		}, spec.Parallel())

		when("the token exchange succeeds", func() {
			var actualToken, actualCaBundle, actualAPIEndpoint string

			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
					actualToken, actualCaBundle, actualAPIEndpoint = token, caBundle, apiEndpoint
					return &clientauthentication.ExecCredential{
						Status: &clientauthentication.ExecCredentialStatus{Token: "some token"},
					}, nil
				}
			})

			it("writes the execCredential to the given writer", func() {
				err := run(envGetter, tokenExchanger, buffer, 30*time.Second)
				require.NoError(t, err)
				require.Equal(t, fakeEnv["PLACEHOLDER_NAME_TOKEN"], actualToken)
				require.Equal(t, fakeEnv["PLACEHOLDER_NAME_CA_BUNDLE"], actualCaBundle)
				require.Equal(t, fakeEnv["PLACEHOLDER_NAME_K8S_API_ENDPOINT"], actualAPIEndpoint)
				expected := `{
					"Spec": {"Interactive": false, "Response": null},
					"Status": {"ClientCertificateData": "", "ClientKeyData": "", "ExpirationTimestamp": null, "Token": "some token"}
				}`
				require.JSONEq(t, expected, buffer.String())
			})
		}, spec.Parallel())
	}, spec.Report(report.Terminal{}))
}
