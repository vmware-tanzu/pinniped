// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.pinniped.dev/test/library"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSupervisorOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.
		ConfigV1alpha1().
		OIDCProviderConfigs(env.Namespace).
		List(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	// 0. Create CRD with single issuer field in config group and generate code.
	// 1. Add test hook that restores these CRDs at the end of the test.
	// 2. Get all CRDs and save them in an array somewhere; also delete them after we store them.
	// 3. Test behavior of when we have no CRD - make sure we get the status code that we want back
	// from the discovery endpoint?
	// 4. Add a CRD with a known issuer.
	// 5. Test behavior of when we have a CRD - make sure we get the status code and response body
	// that we want back from the discovery endpoint?
}
