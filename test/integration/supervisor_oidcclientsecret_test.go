// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestOIDCClientSecretRequest_HappyPath_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := testlib.NewVirtualSupervisorClientset(t)

	response, err := client.OauthV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&v1alpha1.OIDCClientSecretRequest{
			Spec: v1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	// the hardcoded values from the nonfunctional request
	require.Equal(t, response.Status.TotalClientSecrets, 20)
	require.Equal(t, response.Status.GeneratedSecret, "not-a-real-secret")
}

func TestOIDCClientSecretRequest_Unauthenticated_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := testlib.NewAnonymousVirtualSupervisorClientset(t)

	_, err := client.OauthV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&v1alpha1.OIDCClientSecretRequest{
			Spec: v1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
			},
		}, metav1.CreateOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "User \"system:anonymous\" cannot create resource \"oidcclientsecretrequests\"")
}
