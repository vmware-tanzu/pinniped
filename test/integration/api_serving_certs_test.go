/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/placeholder-name/kubernetes/1.19/api/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestAPIServingCertificateAutoCreationAndRotation(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.Getenv(t, "PLACEHOLDER_NAME_NAMESPACE")

	kubeClient := library.NewClientset(t)
	aggregatedClient := library.NewAggregatedClientset(t)
	placeholderClient := library.NewPlaceholderNameClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const apiServiceName = "v1alpha1.placeholder.suzerain-io.github.io"

	// Get the initial auto-generated version of the Secret.
	secret, err := kubeClient.CoreV1().Secrets(namespaceName).Get(ctx, "api-serving-cert", metav1.GetOptions{})
	require.NoError(t, err)
	initialCACert := secret.Data["caCertificate"]
	initialPrivateKey := secret.Data["tlsPrivateKey"]
	initialCertChain := secret.Data["tlsCertificateChain"]
	require.NotEmpty(t, initialCACert)
	require.NotEmpty(t, initialPrivateKey)
	require.NotEmpty(t, initialCertChain)

	// Check that the APIService has the same CA.
	apiService, err := aggregatedClient.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, initialCACert, apiService.Spec.CABundle)

	// Delete the Secret, simulating an end user doing `kubectl delete` to manually ask for an immediate rotation.
	err = kubeClient.CoreV1().Secrets(namespaceName).Delete(ctx, "api-serving-cert", metav1.DeleteOptions{})
	require.NoError(t, err)

	// Expect that the Secret comes back right away with newly minted certs.
	var secretIsRegenerated = func() bool {
		secret, err = kubeClient.CoreV1().Secrets(namespaceName).Get(ctx, "api-serving-cert", metav1.GetOptions{})
		return err == nil
	}
	assert.Eventually(t, secretIsRegenerated, 10*time.Second, 250*time.Millisecond)
	require.NoError(t, err) // prints out the error in case of failure
	regeneratedCACert := secret.Data["caCertificate"]
	regeneratedPrivateKey := secret.Data["tlsPrivateKey"]
	regeneratedCertChain := secret.Data["tlsCertificateChain"]
	require.NotEmpty(t, regeneratedCACert)
	require.NotEmpty(t, regeneratedPrivateKey)
	require.NotEmpty(t, regeneratedCertChain)
	require.NotEqual(t, initialCACert, regeneratedCACert)
	require.NotEqual(t, initialPrivateKey, regeneratedPrivateKey)
	require.NotEqual(t, initialCertChain, regeneratedCertChain)

	// Expect that the APIService was also updated with the new CA.
	var aggregatedAPIUpdated = func() bool {
		apiService, err = aggregatedClient.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
		return err == nil
	}
	assert.Eventually(t, aggregatedAPIUpdated, 10*time.Second, 250*time.Millisecond)
	require.NoError(t, err) // prints out the error in case of failure
	require.Equal(t, regeneratedCACert, apiService.Spec.CABundle)

	// Check that we can still make requests to the aggregated API through the kube API server,
	// because the kube API server uses these certs when proxying requests to the aggregated API server,
	// so this is effectively checking that the aggregated API server is using these new certs.
	var aggregatedAPIWorking = func() bool {
		_, err = placeholderClient.PlaceholderV1alpha1().CredentialRequests().Create(ctx, &v1alpha1.CredentialRequest{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{},
			Spec: v1alpha1.CredentialRequestSpec{
				Type:  v1alpha1.TokenCredentialType,
				Token: &v1alpha1.CredentialRequestTokenCredential{Value: "not a good token"},
			},
		}, metav1.CreateOptions{})
		// Should have got a success response with an error message inside it complaining about the token value.
		return err == nil
	}
	// Unfortunately, although our code changes all the certs immediately, it seems to take ~1 minute for
	// the API machinery to notice that we updated our serving cert, causing 1 minute of downtime for our endpoint.
	assert.Eventually(t, aggregatedAPIWorking, 2*time.Minute, 250*time.Millisecond)
	require.NoError(t, err) // prints out the error in case of failure
}
