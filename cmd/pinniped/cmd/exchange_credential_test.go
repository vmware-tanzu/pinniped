// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
)

var (
	knownGoodUsageForExchangeCredential = here.Doc(`
		Usage:
		  exchange-credential [flags]

		Flags:
		  -h, --help   help for exchange-credential

		`)

	knownGoodHelpForExchangeCredential = here.Doc(`
		Exchange a credential which proves your identity for a time-limited,
		cluster-specific access credential.

		Designed to be conveniently used as an credential plugin for kubectl.
		See the help message for 'pinniped get-kubeconfig' for more
		information about setting up a kubeconfig file using Pinniped.

		Requires all of the following environment variables, which are
		typically set in the kubeconfig:
		  - PINNIPED_TOKEN: the token to send to Pinniped for exchange
		  - PINNIPED_NAMESPACE: the namespace of the authenticator to authenticate
		    against
		  - PINNIPED_AUTHENTICATOR_TYPE: the type of authenticator to authenticate
		    against (e.g., "webhook", "jwt")
		  - PINNIPED_AUTHENTICATOR_NAME: the name of the authenticator to authenticate
		    against
		  - PINNIPED_CA_BUNDLE: the CA bundle to trust when calling
			Pinniped's HTTPS endpoint
		  - PINNIPED_K8S_API_ENDPOINT: the URL for the Pinniped credential
			exchange API

		For more information about credential plugins in general, see
		https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins

		Usage:
		  exchange-credential [flags]

		Flags:
		  -h, --help   help for exchange-credential
	`)
)

func TestNewCredentialExchangeCmd(t *testing.T) {
	spec.Run(t, "newCredentialExchangeCmd", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var stdout, stderr *bytes.Buffer

		it.Before(func() {
			r = require.New(t)

			stdout, stderr = bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{})
		})

		it("calls runFunc and does not print usage or help when correct arguments and flags are used", func() {
			c := newExchangeCredentialCmd([]string{}, stdout, stderr)

			runFuncCalled := false
			c.runFunc = func(out, err io.Writer) {
				runFuncCalled = true
			}

			r.NoError(c.cmd.Execute())
			r.True(runFuncCalled)
			r.Empty(stdout.String())
			r.Empty(stderr.String())
		})

		it("fails when args are passed", func() {
			c := newExchangeCredentialCmd([]string{"some-arg"}, stdout, stderr)

			runFuncCalled := false
			c.runFunc = func(out, err io.Writer) {
				runFuncCalled = true
			}

			errorMessage := `unknown command "some-arg" for "exchange-credential"`
			r.EqualError(c.cmd.Execute(), errorMessage)
			r.False(runFuncCalled)

			output := "Error: " + errorMessage + "\n" + knownGoodUsageForExchangeCredential
			r.Equal(output, stdout.String())
			r.Empty(stderr.String())
		})

		it("prints a nice help message", func() {
			c := newExchangeCredentialCmd([]string{"--help"}, stdout, stderr)

			runFuncCalled := false
			c.runFunc = func(out, err io.Writer) {
				runFuncCalled = true
			}

			r.NoError(c.cmd.Execute())
			r.False(runFuncCalled)
			r.Equal(knownGoodHelpForExchangeCredential, stdout.String())
			r.Empty(stderr.String())
		})
	}, spec.Sequential(), spec.Report(report.Terminal{}))
}

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
				"PINNIPED_NAMESPACE":          "namespace from env",
				"PINNIPED_AUTHENTICATOR_TYPE": "Webhook",
				"PINNIPED_AUTHENTICATOR_NAME": "webhook name from env",
				"PINNIPED_TOKEN":              "token from env",
				"PINNIPED_CA_BUNDLE":          "ca bundle from env",
				"PINNIPED_K8S_API_ENDPOINT":   "k8s api from env",
			}
		})

		when("env vars are missing", func() {
			it("returns an error when PINNIPED_NAMESPACE is missing", func() {
				delete(fakeEnv, "PINNIPED_NAMESPACE")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_NAMESPACE")
			})

			it("returns an error when PINNIPED_AUTHENTICATOR_TYPE is missing", func() {
				delete(fakeEnv, "PINNIPED_AUTHENTICATOR_TYPE")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_AUTHENTICATOR_TYPE")
			})

			it("returns an error when PINNIPED_AUTHENTICATOR_NAME is missing", func() {
				delete(fakeEnv, "PINNIPED_AUTHENTICATOR_NAME")
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, "failed to get credential: environment variable not set: PINNIPED_AUTHENTICATOR_NAME")
			})

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

		when("env vars are invalid", func() {
			it("returns an error when PINNIPED_AUTHENTICATOR_TYPE is missing", func() {
				fakeEnv["PINNIPED_AUTHENTICATOR_TYPE"] = "invalid"
				err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
				r.EqualError(err, `invalid authenticator type: "invalid", supported values are "webhook" and "jwt"`)
			})
		})

		when("the token exchange fails", func() {
			it.Before(func() {
				tokenExchanger = func(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
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
				tokenExchanger = func(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
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
				tokenExchanger = func(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
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
			var actualNamespace, actualToken, actualCaBundle, actualAPIEndpoint string

			it.Before(func() {
				tokenExchanger = func(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					actualNamespace, actualToken, actualCaBundle, actualAPIEndpoint = namespace, token, caBundle, apiEndpoint
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
				r.Equal(fakeEnv["PINNIPED_NAMESPACE"], actualNamespace)
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

		when("the authenticator info is passed", func() {
			var actualAuthenticator corev1.TypedLocalObjectReference

			it.Before(func() {
				tokenExchanger = func(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
					actualAuthenticator = authenticator
					return nil, nil
				}
			})

			when("the authenticator is of type webhook", func() {
				it.Before(func() {
					fakeEnv["PINNIPED_AUTHENTICATOR_TYPE"] = "webhook"
					fakeEnv["PINNIPED_AUTHENTICATOR_NAME"] = "some-webhook-name"
				})

				it("passes the correct authenticator type to the token exchanger", func() {
					err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
					r.NoError(err)
					require.Equal(t, corev1.TypedLocalObjectReference{
						APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
						Kind:     "WebhookAuthenticator",
						Name:     "some-webhook-name",
					}, actualAuthenticator)
				})
			})

			when("the authenticator is of type jwt", func() {
				it.Before(func() {
					fakeEnv["PINNIPED_AUTHENTICATOR_TYPE"] = "jwt"
					fakeEnv["PINNIPED_AUTHENTICATOR_NAME"] = "some-jwt-authenticator-name"
				})

				it("passes the correct authenticator type to the token exchanger", func() {
					err := exchangeCredential(envGetter, tokenExchanger, buffer, 30*time.Second)
					r.NoError(err)
					require.Equal(t, corev1.TypedLocalObjectReference{
						APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
						Kind:     "JWTAuthenticator",
						Name:     "some-jwt-authenticator-name",
					}, actualAuthenticator)
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
