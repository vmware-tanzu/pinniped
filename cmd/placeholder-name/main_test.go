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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/suzerain-io/placeholder-name/test/library"
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
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
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
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					return &clientauthenticationv1beta1.ExecCredential{
						Status: &clientauthenticationv1beta1.ExecCredentialStatus{Token: "some token"},
					}, nil
				}
			})

			it("returns an error", func() {
				err := run(envGetter, tokenExchanger, &library.ErrorWriter{ReturnError: fmt.Errorf("some IO error")}, 30*time.Second)
				r.EqualError(err, "failed to marshal response to stdout: some IO error")
			})
		})

		when("the token exchange times out", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					select {
					case <-time.After(100 * time.Millisecond):
						return &clientauthenticationv1beta1.ExecCredential{
							Status: &clientauthenticationv1beta1.ExecCredentialStatus{Token: "some token"},
						}, nil
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
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					actualToken, actualCaBundle, actualAPIEndpoint = token, caBundle, apiEndpoint
					return &clientauthenticationv1beta1.ExecCredential{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ExecCredential",
							APIVersion: "client.authentication.k8s.io/v1beta1",
						},
						Status: &clientauthenticationv1beta1.ExecCredentialStatus{Token: "some token"},
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
					"token": "some token"
				  }
				}`
				r.JSONEq(expected, buffer.String())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
