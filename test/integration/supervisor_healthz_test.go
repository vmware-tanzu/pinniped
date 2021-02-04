// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/library"
)

// The Supervisor health endpoint is public because that makes it easier
// for users to create an Ingress for the supervisor on platforms like
// GKE where the Ingress wants to perform a health check. It's somewhere
// between inconvenient and impossible to make that Ingress health check
// happen on a private container port at this time.
// This test checks that it is working and that it is public.
func TestSupervisorHealthz(t *testing.T) {
	env := library.IntegrationEnv(t)

	if env.SupervisorHTTPAddress == "" {
		t.Skip("PINNIPED_TEST_SUPERVISOR_HTTP_ADDRESS not defined")
	}

	library.AssertNoRestartsDuringTest(t, env.SupervisorNamespace, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	requestHealthEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://%s/healthz", env.SupervisorHTTPAddress),
		nil,
	)
	require.NoError(t, err)

	httpClient := &http.Client{}
	response, err := httpClient.Do(requestHealthEndpoint) //nolint:bodyclose
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	responseBody, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	err = response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "ok", string(responseBody))
}
