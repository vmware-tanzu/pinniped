// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/test/library"
)

// Test certificate and private key that should get an authentication error. Generated with cfssl [1], like this:
//
// 	$ brew install cfssl
// 	$ cfssl print-defaults csr | cfssl genkey -initca - | cfssljson -bare ca
// 	$ cfssl print-defaults csr | cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=testuser - | cfssljson -bare client
// 	$ cat client.pem client-key.pem
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
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	library.AssertNoRestartsDuringTest(t, env.ConciergeNamespace, "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	webhook := library.CreateTestWebhookAuthenticator(ctx, t)

	// Use an invalid certificate/key to validate that the ServerVersion API fails like we assume.
	invalidClient := library.NewClientsetWithCertAndKey(t, testCert, testKey)
	_, err := invalidClient.Discovery().ServerVersion()
	require.EqualError(t, err, "the server has asked for the client to provide credentials")

	// Using the CA bundle and host from the current (admin) kubeconfig, do the token exchange.
	clientConfig := library.NewClientConfig(t)
	client, err := conciergeclient.New(
		conciergeclient.WithCABundle(string(clientConfig.CAData)),
		conciergeclient.WithEndpoint(clientConfig.Host),
		conciergeclient.WithAuthenticator("webhook", webhook.Name),
		conciergeclient.WithAPIGroupSuffix(env.APIGroupSuffix),
	)
	require.NoError(t, err)

	var resp *clientauthenticationv1beta1.ExecCredential
	assert.Eventually(t, func() bool {
		resp, err = client.ExchangeToken(ctx, env.TestUser.Token)
		return err == nil
	}, 10*time.Second, 500*time.Millisecond)
	require.NoError(t, err)

	require.NotNil(t, resp.Status.ExpirationTimestamp)
	require.InDelta(t, 5*time.Minute, time.Until(resp.Status.ExpirationTimestamp.Time), float64(time.Minute))

	// Create a client using the certificate and key returned by the token exchange.
	validClient := library.NewClientsetWithCertAndKey(t, resp.Status.ClientCertificateData, resp.Status.ClientKeyData)

	// Make a version request, which should succeed even without any authorization.
	_, err = validClient.Discovery().ServerVersion()
	require.NoError(t, err)
}
