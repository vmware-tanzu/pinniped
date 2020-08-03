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

	crdsplaceholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/crdsplaceholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestSuccessfulLoginDiscoveryConfig(t *testing.T) {
	namespaceName := library.Getenv(t, "PLACEHOLDER_NAME_NAMESPACE")
	discoveryURL := library.Getenv(t, "PLACEHOLDER_NAME_DISCOVERY_URL")

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := library.NewClientConfig(t)
	expectedLDCSpec := expectedLDCSpec(config, discoveryURL)
	configList, err := client.
		CrdsV1alpha1().
		LoginDiscoveryConfigs(namespaceName).
		List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, configList.Items, 1)
	require.Equal(t, expectedLDCSpec, &configList.Items[0].Spec)
}

func TestReconcilingLoginDiscoveryConfig(t *testing.T) {
	namespaceName := library.Getenv(t, "PLACEHOLDER_NAME_NAMESPACE")
	discoveryURL := library.Getenv(t, "PLACEHOLDER_NAME_DISCOVERY_URL")

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.
		CrdsV1alpha1().
		LoginDiscoveryConfigs(namespaceName).
		Delete(ctx, "placeholder-name-config", metav1.DeleteOptions{})
	require.NoError(t, err)

	config := library.NewClientConfig(t)
	expectedLDCSpec := expectedLDCSpec(config, discoveryURL)

	var actualLDC *crdsplaceholderv1alpha1.LoginDiscoveryConfig
	for i := 0; i < 10; i++ {
		actualLDC, err = client.
			CrdsV1alpha1().
			LoginDiscoveryConfigs(namespaceName).
			Get(ctx, "placeholder-name-config", metav1.GetOptions{})
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond * 750)
	}
	require.NoError(t, err)
	require.Equal(t, expectedLDCSpec, &actualLDC.Spec)
}

func expectedLDCSpec(config *rest.Config, discoveryURL string) *crdsplaceholderv1alpha1.LoginDiscoveryConfigSpec {
	return &crdsplaceholderv1alpha1.LoginDiscoveryConfigSpec{
		Server:                   discoveryURL,
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
	}
}
