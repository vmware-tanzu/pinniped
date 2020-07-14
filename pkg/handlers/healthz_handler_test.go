/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package handlers_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/placeholder-name/pkg/handlers"
)

func TestHealthzReturnsOkWithJsonBody(t *testing.T) {
	expect := require.New(t)
	server := httptest.NewServer(handlers.New())
	defer server.Close()

	// Create a request context with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Initialize an HTTP GET request to /healthz
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/healthz", nil)
	expect.NoError(err)

	// Perform the request and assert that we received a response.
	response, err := http.DefaultClient.Do(req)
	expect.NoError(err)
	defer response.Body.Close()

	// Assert that we got an HTTP 200 with the correct content type and JSON body.
	expect.Equal(http.StatusOK, response.StatusCode)
	expect.Equal("application/json; charset=utf-8", response.Header.Get("content-type"))
	body, err := ioutil.ReadAll(response.Body)
	expect.NoError(err)
	expect.JSONEq(`{"status": "OK - FAIL CI 3"}`, string(body))
}
