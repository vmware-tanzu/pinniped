// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/testlib"
)

// Never run this test in parallel since deleting all federation domains and the default TLS secret is disruptive, see main_test.go.
func TestSupervisorHealthzBootstrap_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	pinnipedClient := testlib.NewSupervisorClientset(t)
	kubeClient := testlib.NewKubernetesClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t, ns, env.DefaultTLSCertSecretName(), pinnipedClient, kubeClient)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // there is no way for us to know the bootstrap CA
		},
	}

	const badTLSConfigBody = "pinniped supervisor has invalid TLS serving certificate configuration\n"

	httpGet(ctx, t, httpClient, fmt.Sprintf("https://%s/healthz", env.SupervisorHTTPSAddress), http.StatusOK, "ok")
	httpGet(ctx, t, httpClient, fmt.Sprintf("https://%s", env.SupervisorHTTPSAddress), http.StatusInternalServerError, badTLSConfigBody)
	httpGet(ctx, t, httpClient, fmt.Sprintf("https://%s/nothealthz", env.SupervisorHTTPSAddress), http.StatusInternalServerError, badTLSConfigBody)
	httpGet(ctx, t, httpClient, fmt.Sprintf("https://%s/healthz/something", env.SupervisorHTTPSAddress), http.StatusInternalServerError, badTLSConfigBody)
}

func httpGet(ctx context.Context, t *testing.T, client *http.Client, url string, expectedStatus int, expectedBody string) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil,
	)
	require.NoError(t, err)

	response, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, expectedStatus, response.StatusCode)

	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	err = response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, expectedBody, string(responseBody))
}
