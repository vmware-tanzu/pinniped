/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestLogin(t *testing.T) {
	tmcClusterToken := os.Getenv("PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN")
	require.NotEmptyf(t, namespaceName, "must specify PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN env var for integration tests")

	kubeCredential := getKubeCredential(t, tmcClusterToken)
	useKubeCredential(t, kubeCredential)
}

func getKubeCredential(t *testing.T, tmcClusterToken string) *placeholdernamev1alpha1.LoginRequestStatus {
	placeholderClient := library.NewPlaceholderClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := placeholderv1alpha1.LoginRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-login-token",
		},
		Spec: placeholderv1alpha1.LoginRequestSpec{
			Type: placeholderv1alpha1.TokenLoginCredentialType,
			Token: &placeholderv1alpha1.LoginRequestTokenCredential{
				Value: tmcClusterToken,
			},
		},
	}
	rsp, err := placeholderClient.PlaceholderV1alpha1().LoginRequests().Create(ctx, &req, metav1.CreateOptions{})
	require.NoError(t, err)
	return &rsp.Status
}

func useKubeCredential(t *testing.T, credential *placeholdernamev1alpha1.LoginRequestStatus) {
	config := library.NewConfigWithCertificate(t, credential.ClientCertificateData, credential.ClientKeyData)
	client := library.NewClientsetWithConfig(t, config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
}
