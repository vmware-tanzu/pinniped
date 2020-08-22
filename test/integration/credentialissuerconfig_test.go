/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/kubernetes/1.19/api/apis/crdpinniped/v1alpha1"
	"github.com/suzerain-io/pinniped/test/library"
)

func TestSuccessfulCredentialIssuerConfig(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.Getenv(t, "PINNIPED_NAMESPACE")

	client := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := library.NewClientConfig(t)
	expectedLDCStatus := expectedLDCStatus(config)
	configList, err := client.
		CrdV1alpha1().
		CredentialIssuerConfigs(namespaceName).
		List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, configList.Items, 1)
	require.Equal(t, expectedLDCStatus, &configList.Items[0].Status)
}

func TestReconcilingCredentialIssuerConfig(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.Getenv(t, "PINNIPED_NAMESPACE")

	client := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.
		CrdV1alpha1().
		CredentialIssuerConfigs(namespaceName).
		Delete(ctx, "pinniped-config", metav1.DeleteOptions{})
	require.NoError(t, err)

	config := library.NewClientConfig(t)
	expectedLDCStatus := expectedLDCStatus(config)

	var actualLDC *crdpinnipedv1alpha1.CredentialIssuerConfig
	for i := 0; i < 10; i++ {
		actualLDC, err = client.
			CrdV1alpha1().
			CredentialIssuerConfigs(namespaceName).
			Get(ctx, "pinniped-config", metav1.GetOptions{})
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond * 750)
	}
	require.NoError(t, err)
	require.Equal(t, expectedLDCStatus, &actualLDC.Status)
}

func expectedLDCStatus(config *rest.Config) *crdpinnipedv1alpha1.CredentialIssuerConfigStatus {
	return &crdpinnipedv1alpha1.CredentialIssuerConfigStatus{
		Strategies: []crdpinnipedv1alpha1.CredentialIssuerConfigStrategy{},
		KubeConfigInfo: &crdpinnipedv1alpha1.CredentialIssuerConfigKubeConfigInfo{
			Server:                   config.Host,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
		},
	}
}
