// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestSecureTLS(t *testing.T) {
	var sawRequest bool
	server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Secure)
		sawRequest = true
	}), tlsserver.RecordTLSHello)

	config := &rest.Config{
		Host: server.URL,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: tlsserver.TLSTestServerCA(server),
		},
	}

	client, err := kubeclient.New(kubeclient.WithConfig(config))
	require.NoError(t, err)

	// build this exactly like our production could does
	podCommandExecutor := NewPodCommandExecutor(client.JSONConfig, client.Kubernetes)

	got, err := podCommandExecutor.Exec("podNamespace", "podName", "command", "arg1", "arg2")
	require.Equal(t, &errors.StatusError{}, err)
	require.Empty(t, got)

	require.True(t, sawRequest)
}
