// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serviceaccounttokencleanup

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestNewServiceAccountTokenCleanupController(t *testing.T) {
	namespace := "a-namespace"
	legacySecretName := "a-secret"
	observableWithInformerOption := testutil.NewObservableWithInformerOption()
	secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()

	logger, _ := plog.TestLogger(t)
	_ = NewLegacyServiceAccountTokenCleanupController(
		namespace,
		legacySecretName,
		nil, // not needed for this test
		secretsInformer,
		observableWithInformerOption.WithInformer,
		logger,
	)

	secretsInformerFilter := observableWithInformerOption.GetFilterForInformer(secretsInformer)

	legacySecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: legacySecretName, Namespace: namespace}, Type: corev1.SecretTypeServiceAccountToken}
	wrongName := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrongName", Namespace: namespace}, Type: corev1.SecretTypeServiceAccountToken}
	wrongType := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrongType", Namespace: namespace}, Type: "other-type"}
	wrongNamespace := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrongNamespace", Namespace: "wrong-namespace"}, Type: corev1.SecretTypeServiceAccountToken}
	wrongObject := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config-map", Namespace: namespace}}

	require.False(t, secretsInformerFilter.Add(wrongName))
	require.False(t, secretsInformerFilter.Update(wrongName, wrongNamespace))
	require.False(t, secretsInformerFilter.Update(wrongNamespace, wrongName))
	require.False(t, secretsInformerFilter.Delete(wrongName))

	require.False(t, secretsInformerFilter.Add(wrongObject))
	require.False(t, secretsInformerFilter.Update(wrongObject, wrongNamespace))
	require.False(t, secretsInformerFilter.Update(wrongNamespace, wrongObject))
	require.False(t, secretsInformerFilter.Delete(wrongObject))

	require.False(t, secretsInformerFilter.Add(wrongNamespace))
	require.False(t, secretsInformerFilter.Update(wrongNamespace, wrongObject))
	require.False(t, secretsInformerFilter.Update(wrongObject, wrongNamespace))
	require.False(t, secretsInformerFilter.Delete(wrongNamespace))

	require.False(t, secretsInformerFilter.Add(wrongType))
	require.False(t, secretsInformerFilter.Update(wrongType, wrongNamespace))
	require.False(t, secretsInformerFilter.Update(wrongNamespace, wrongType))
	require.False(t, secretsInformerFilter.Delete(wrongType))

	require.True(t, secretsInformerFilter.Add(legacySecret))
	require.True(t, secretsInformerFilter.Update(legacySecret, wrongNamespace))
	require.True(t, secretsInformerFilter.Update(wrongNamespace, legacySecret))
	require.True(t, secretsInformerFilter.Delete(legacySecret))
}

func TestSync(t *testing.T) {
	for _, tt := range []struct {
		name               string
		secretNameToDelete string
		namespace          string
		addReactors        func(*kubernetesfake.Clientset)
		expectedErrMessage string
		expectedActions    []kubetesting.Action
	}{
		{
			name:               "happy path",
			secretNameToDelete: "secret-to-delete",
			namespace:          "some-namespace",
			expectedActions: []kubetesting.Action{
				kubetesting.NewDeleteAction(
					schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "secrets",
					},
					"some-namespace",
					"secret-to-delete",
				),
			},
		},
		{
			name:               "no secret to delete",
			secretNameToDelete: "not-an-existing-secret",
			expectedActions:    []kubetesting.Action{},
		},
		{
			name:               "returns API errors",
			secretNameToDelete: "secret-to-delete",
			namespace:          "other-namespace",
			addReactors: func(clientset *kubernetesfake.Clientset) {
				clientset.PrependReactor(
					"delete",
					"secrets",
					func(a kubetesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("error from API client")
					},
				)
			},
			expectedErrMessage: "unable to delete secret secret-to-delete in namespace other-namespace: error from API client",
			expectedActions: []kubetesting.Action{
				kubetesting.NewDeleteAction(
					schema.GroupVersionResource{
						Group:    "",
						Version:  "v1",
						Resource: "secrets",
					},
					"other-namespace",
					"secret-to-delete",
				),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeAPIClient, kubeInformers := setupKubernetes(t, tt.namespace)
			if tt.addReactors != nil {
				tt.addReactors(kubeAPIClient)
			}

			logger, _ := plog.TestLogger(t)
			controller := NewLegacyServiceAccountTokenCleanupController(
				tt.namespace,
				tt.secretNameToDelete,
				kubeAPIClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				logger,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Must start informers before calling TestRunSynchronously().
			kubeInformers.Start(ctx.Done())

			controllerlib.TestRunSynchronously(t, controller)

			err := controllerlib.TestSync(t, controller, controllerlib.Context{
				Context: ctx,
			})
			if tt.expectedErrMessage == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.expectedErrMessage)
			}

			actualActions := kubeAPIClient.Actions()
			require.Equal(t, tt.expectedActions, actualActions)
		})
	}
}

func setupKubernetes(t *testing.T, namespace string) (*kubernetesfake.Clientset, kubeinformers.SharedInformerFactory) {
	t.Helper()

	kubeAPIClient := kubernetesfake.NewSimpleClientset()
	kubeInformerClient := kubernetesfake.NewSimpleClientset()

	kubeInformers := kubeinformers.NewSharedInformerFactory(
		kubeInformerClient,
		0,
	)

	secretToDelete := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-to-delete",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	secretWithWrongName := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wrong-name",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
	secretWithWrongType := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-to-leave-alone",
			Namespace: namespace,
		},
	}
	secretWithWrongNamespace := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-to-delete",
			Namespace: "other",
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	require.NoError(t, kubeAPIClient.Tracker().Add(secretToDelete))
	require.NoError(t, kubeInformerClient.Tracker().Add(secretToDelete))
	require.NoError(t, kubeAPIClient.Tracker().Add(secretWithWrongName))
	require.NoError(t, kubeInformerClient.Tracker().Add(secretWithWrongName))
	require.NoError(t, kubeAPIClient.Tracker().Add(secretWithWrongType))
	require.NoError(t, kubeInformerClient.Tracker().Add(secretWithWrongType))
	require.NoError(t, kubeAPIClient.Tracker().Add(secretWithWrongNamespace))
	require.NoError(t, kubeInformerClient.Tracker().Add(secretWithWrongNamespace))
	return kubeAPIClient, kubeInformers
}
