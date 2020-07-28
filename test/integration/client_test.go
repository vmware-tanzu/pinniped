/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/placeholder-name/pkg/client"
	"github.com/suzerain-io/placeholder-name/test/library"
)

var (
	// Test certificate and private key that should get an authentication error. Generated with
	// https://github.com/cloudflare/cfssl, like this:
	// $ brew install cfssl
	// $ cfssl print-defaults csr | cfssl genkey -initca - | cfssljson -bare ca
	// $ cfssl print-defaults csr | cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=testuser - | cfssljson -bare client
	// $ cat client.pem client-key.pem

	testCert = strings.TrimSpace(`
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

	testKey = strings.TrimSpace(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAqkBGGKTH5GzLx8XZLAHEFW2E8jT+jpy0p6w6MMR7DkoAoGCCqGSM49
AwEHoUQDQgAEZO1wQvjo2Jq1zoZu0WiYh1uEOVbBPojFfdAc6u2p7KgIW9OESOt2
O2D8LtWhMbrYy755Fgq4H9s3vCgfvHY1AQ==
-----END EC PRIVATE KEY-----
	`)
)

func TestClient(t *testing.T) {
	tmcClusterToken := os.Getenv("PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN")
	require.NotEmptyf(t, tmcClusterToken, "must specify PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN env var for integration tests")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use an invalid certificate/key to validate that the ServerVersion API fails like we assume.
	invalidClient := library.NewClientsetWithConfig(t, library.NewClientConfigWithCertAndKey(t, testCert, testKey))
	_, err := invalidClient.Discovery().ServerVersion()
	require.EqualError(t, err, "the server has asked for the client to provide credentials")

	// Using the CA bundle and host from the current (admin) kubeconfig, do the token exchange.
	clientConfig := library.NewClientConfig(t)
	resp, err := client.ExchangeToken(ctx, tmcClusterToken, string(clientConfig.CAData), clientConfig.Host)
	require.NoError(t, err)

	// Create a client using the certificate and key returned by the token exchange.
	validClient := library.NewClientsetWithConfig(t, library.NewClientConfigWithCertAndKey(t, resp.Status.ClientCertificateData, resp.Status.ClientKeyData))

	// Make a version request, which should succeed even without any authorization.
	_, err = validClient.Discovery().ServerVersion()
	require.NoError(t, err)
}
