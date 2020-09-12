/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

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

	"github.com/suzerain-io/pinniped/internal/testutil"
)

func TestExchangeCredential(t *testing.T) {
	spec.Run(t, "cmd.exchangeCredential", func(t *testing.T, when spec.G, it spec.S) {
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
				"PINNIPED_TOKEN":            "token from env",
				"PINNIPED_CA_BUNDLE":        "ca bundle from env",
				"PINNIPED_K8S_API_ENDPOINT": "k8s api from env",
			}
		})

		when("env vars are missing", func() {
			it("returns an error when PINNIPED_TOKEN is missing", func() {
				delete(fakeEnv, "PINNIPED_TOKEN")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_TOKEN")
			})

			it("returns an error when PINNIPED_CA_BUNDLE is missing", func() {
				delete(fakeEnv, "PINNIPED_CA_BUNDLE")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_CA_BUNDLE")
			})

			it("returns an error when PINNIPED_K8S_API_ENDPOINT is missing", func() {
				delete(fakeEnv, "PINNIPED_K8S_API_ENDPOINT")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_K8S_API_ENDPOINT")
			})
		})

		when("the token exchange fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					return nil, fmt.Errorf("some error")
				}
			})

			it("returns an error", func() {
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: some error")
			})
		})

		when("the JSON encoder fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					return &clientauthenticationv1beta1.ExecCredential{
						Status: &clientauthenticationv1beta1.ExecCredentialStatus{
							Token: "some token",
						},
					}, nil
				}
			})

			it("returns an error", func() {
				err := exchangeCredential(envGetter, tokenExchanger, &testutil.ErrorWriter{ReturnError: fmt.Errorf("some IO error")}, 30*time.Second)
				r.EqualError(err, "failed to marshal response to stdout: some IO error")
			})
		})

		when("the token exchange times out", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					select {
					case <-time.After(100 * time.Millisecond):
						return &clientauthenticationv1beta1.ExecCredential{
							Status: &clientauthenticationv1beta1.ExecCredentialStatus{
								Token: "some token",
							},
						}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			})

			it("returns an error", func() {
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 1*time.Millisecond)
				r.EqualError(err, "failed to get credential: context deadline exceeded")
			})
		})

		when("the token exchange succeeds", func() {
			var actualToken, actualCaBundle, actualAPIEndpoint string

			it.Before(func() {
				tokenExchanger = func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					actualToken, actualCaBundle, actualAPIEndpoint = token, caBundle, apiEndpoint
					now := metav1.NewTime(time.Date(2020, 7, 29, 1, 2, 3, 0, time.UTC))
					return &clientauthenticationv1beta1.ExecCredential{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ExecCredential",
							APIVersion: "client.authentication.k8s.io/v1beta1",
						},
						Status: &clientauthenticationv1beta1.ExecCredentialStatus{
							ExpirationTimestamp:   &now,
							ClientCertificateData: "some certificate",
							ClientKeyData:         "some key",
							Token:                 "some token",
						},
					}, nil
				}
			})

			it("writes the execCredential to the given writer", func() {
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.NoError(err)
				r.Equal(fakeEnv["PINNIPED_TOKEN"], actualToken)
				r.Equal(fakeEnv["PINNIPED_CA_BUNDLE"], actualCaBundle)
				r.Equal(fakeEnv["PINNIPED_K8S_API_ENDPOINT"], actualAPIEndpoint)
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
