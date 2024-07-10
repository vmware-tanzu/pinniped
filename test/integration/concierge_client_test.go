// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/test/testlib"
)

// Test certificate and private key that should get an authentication error. Generated with cfssl [1], like this:
//
//	$ brew install cfssl
//	$ cfssl print-defaults csr | cfssl genkey -initca - | cfssljson -bare ca
//	$ cfssl print-defaults csr | cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=testuser - | cfssljson -bare client
//	$ cat client.pem client-key.pem
//
// [1]: https://github.com/cloudflare/cfssl
var (
	testCert = here.Doc(`
		-----BEGIN CERTIFICATE-----
		MIICBDCCAaugAwIBAgIUeidKWlZQuoKfBGydObI1hMwzt9cwCgYIKoZIzj0EAwIw
		SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
		c2NvMRQwEgYDVQQDEwtleGFtcGxlLm5ldDAeFw0yMDA3MjgxOTI3MDBaFw0yMTA3
		MjgxOTI3MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
		U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZXhhbXBsZS5uZXQwWTATBgcqhkjOPQIB
		BggqhkjOPQMBBwNCAARk7XBC+OjYmrXOhm7RaJiHW4Q5VsE+iMV90Bzq7ansqAhb
		04RI63Y7YPwu1aExutjLvnkWCrgf2ze8KB+8djUBo3MwcTAOBgNVHQ8BAf8EBAMC
		BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw
		HQYDVR0OBBYEFG0oZxV+LHUKfE4gQ67xfHJuGQ/4MBMGA1UdEQQMMAqCCHRlc3R1
		c2VyMAoGCCqGSM49BAMCA0cAMEQCIEwPZhPpYhYHndfTEsWOxnxzJkmhAcYIMCeJ
		d9kyq/fPAiBNCJw1MCLT8LjNlyUZCfwI2zuI3e0w6vuau89oj2zvVA==
		-----END CERTIFICATE-----
	`)

	testKey = maskKey(here.Doc(`
		-----BEGIN EC TESTING KEY-----
		MHcCAQEEIAqkBGGKTH5GzLx8XZLAHEFW2E8jT+jpy0p6w6MMR7DkoAoGCCqGSM49
		AwEHoUQDQgAEZO1wQvjo2Jq1zoZu0WiYh1uEOVbBPojFfdAc6u2p7KgIW9OESOt2
		O2D8LtWhMbrYy755Fgq4H9s3vCgfvHY1AQ==
		-----END EC TESTING KEY-----
	`))
)

var maskKey = func(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func TestClient(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	defaultWebhook := &testlib.IntegrationEnv(t).TestWebhook
	TLSCABundle, err := base64.StdEncoding.DecodeString(env.TestWebhook.TLS.CertificateAuthorityData)
	require.NoError(t, err)

	tests := []struct {
		name string
		edit func(t *testing.T, spec *authenticationv1alpha1.WebhookAuthenticatorSpec)
	}{
		{
			name: "default webhook authenticator",
			edit: nil,
		},
		{
			name: "webhook authenticator with secret of type TLS to source ca bundle",
			edit: func(t *testing.T, spec *authenticationv1alpha1.WebhookAuthenticatorSpec) {
				caSecret := testlib.CreateTestSecret(t, env.ConciergeNamespace, "ca-cert", corev1.SecretTypeTLS,
					map[string]string{
						"ca.crt":  string(TLSCABundle),
						"tls.crt": "",
						"tls.key": "",
					})
				spec.TLS.CertificateAuthorityData = ""
				spec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: caSecret.Name,
					Key:  "ca.crt",
				}
			},
		},
		{
			name: "webhook authenticator with secret of type opaque to source ca bundle",
			edit: func(t *testing.T, spec *authenticationv1alpha1.WebhookAuthenticatorSpec) {
				caSecret := testlib.CreateTestSecret(t, env.ConciergeNamespace, "ca-cert", corev1.SecretTypeOpaque,
					map[string]string{
						"ca.crt": string(TLSCABundle),
					})
				spec.TLS.CertificateAuthorityData = ""
				spec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: caSecret.Name,
					Key:  "ca.crt",
				}
			},
		},
		{
			name: "webhook authenticator with configmap to source ca bundle",
			edit: func(t *testing.T, spec *authenticationv1alpha1.WebhookAuthenticatorSpec) {
				caConfigmap := testlib.CreateTestConfigMap(t, env.ConciergeNamespace, "ca-cert",
					map[string]string{
						"ca.crt": string(TLSCABundle),
					})
				spec.TLS.CertificateAuthorityData = ""
				spec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CABundleSource{
					Kind: "ConfigMap",
					Name: caConfigmap.Name,
					Key:  "ca.crt",
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			webhookSpec := defaultWebhook.DeepCopy()
			if test.edit != nil {
				test.edit(t, webhookSpec)
			}
			webhook := testlib.CreateTestWebhookAuthenticator(ctx, t, webhookSpec, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

			// Use an invalid certificate/key to validate that the ServerVersion API fails like we assume.
			invalidClient := testlib.NewClientsetWithCertAndKey(t, testCert, testKey)
			_, err := invalidClient.Discovery().ServerVersion()
			require.EqualError(t, err, "the server has asked for the client to provide credentials")

			// Using the CA bundle and host from the current (admin) kubeconfig, do the token exchange.
			clientConfig := testlib.NewClientConfig(t)
			client, err := conciergeclient.New(
				conciergeclient.WithCABundle(string(clientConfig.CAData)),
				conciergeclient.WithEndpoint(clientConfig.Host),
				conciergeclient.WithAuthenticator("webhook", webhook.Name),
				conciergeclient.WithAPIGroupSuffix(env.APIGroupSuffix),
			)
			require.NoError(t, err)

			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				resp, err := client.ExchangeToken(ctx, env.TestUser.Token)
				requireEventually.NoError(err)
				requireEventually.NotNil(resp.Status.ExpirationTimestamp)
				requireEventually.InDelta(5*time.Minute, time.Until(resp.Status.ExpirationTimestamp.Time), float64(time.Minute))

				// Create a client using the certificate and key returned by the token exchange.
				validClient := testlib.NewClientsetWithCertAndKey(t, resp.Status.ClientCertificateData, resp.Status.ClientKeyData)

				// Make a version request, which should succeed even without any authorization.
				_, err = validClient.Discovery().ServerVersion()
				requireEventually.NoError(err)
			}, 10*time.Second, 500*time.Millisecond)
		})
	}
}
