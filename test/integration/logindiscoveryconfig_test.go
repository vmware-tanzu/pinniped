/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestSuccessfulLoginDiscoveryConfig(t *testing.T) {
	namespaceName := os.Getenv("PLACEHOLDER_NAME_NAMESPACE")
	require.NotEmptyf(t, namespaceName, "must specify PLACEHOLDER_NAME_NAMESPACE env var for integration tests")

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// TODO(akeesler): is there a race here between this test running and the
	// placeholder-name-server creating the CR?

	config := library.NewClientConfig(t)
	expectedLDC := getExpectedLDC(namespaceName, config)
	configList, err := client.
		PlaceholderV1alpha1().
		LoginDiscoveryConfigs(namespaceName).
		List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, configList.Items, 1)
	require.Equal(t, expectedLDC, configList.Items[0])
}

func TestReconcilingLoginDiscoveryConfig(t *testing.T) {
	t.Skip()

	namespaceName := os.Getenv("PLACEHOLDER_NAME_NAMESPACE")
	require.NotEmptyf(t, namespaceName, "must specify PLACEHOLDER_NAME_NAMESPACE env var for integration tests")

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// TODO(akeesler): is there a race here between this test running and the
	// placeholder-name-server creating the CR?

	w, err := client.
		PlaceholderV1alpha1().
		LoginDiscoveryConfigs(namespaceName).
		Watch(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	err = client.
		PlaceholderV1alpha1().
		LoginDiscoveryConfigs(namespaceName).
		Delete(ctx, "placeholder-name-config", metav1.DeleteOptions{})
	require.NoError(t, err)

	config := library.NewClientConfig(t)
	expectedLDC := getExpectedLDC(namespaceName, config)
	received := func(et watch.EventType, o runtime.Object) func() bool {
		return func() bool {
			select {
			case e := <-w.ResultChan():
				require.Equal(t, et, e.Type)
				require.Equal(t, o, e.Object)
				return true
			default:
				return false
			}
		}
	}
	require.Eventually(
		t,
		received(watch.Deleted, expectedLDC),
		time.Second,
		3*time.Second,
	)
	require.Eventually(
		t,
		received(watch.Added, expectedLDC),
		time.Second,
		3*time.Second,
	)
}

func getExpectedLDC(
	namespaceName string,
	config *rest.Config,
) *placeholderv1alpha1.LoginDiscoveryConfig {
	return &placeholderv1alpha1.LoginDiscoveryConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placeholder-name-config",
			Namespace: namespaceName,
		},
		Spec: placeholderv1alpha1.LoginDiscoveryConfigSpec{
			Server:                   config.Host,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
		},
	}
}
