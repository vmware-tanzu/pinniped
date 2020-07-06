/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package handlers_test

import (
	"github.com/stretchr/testify/require"
	"github.com/suzerain-io/placeholder-name/pkg/handlers"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzReturnsOkWithJsonBody(t *testing.T) {
	expect := require.New(t)
	server := httptest.NewServer(handlers.New())
	defer server.Close()
	client := http.Client{}

	response, err := client.Get(server.URL + "/healthz")

	expect.NoError(err)
	expect.Equal(http.StatusOK, response.StatusCode)
	expect.Equal("application/json; charset=utf-8", response.Header.Get("content-type"))
	body, err := ioutil.ReadAll(response.Body)
	expect.NoError(err)
	expect.JSONEq(`{"status": "OK"}`, string(body))
}
