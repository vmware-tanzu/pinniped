// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secretgenerator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
)

func TestController(t *testing.T) {
	const (
		generatedSecretNamespace  = "some-namespace"
		generatedSecretNamePrefix = "some-name-"
		generatedSecretName       = "some-name-abc123"
	)

	var (
		secretsGVR = schema.GroupVersionResource{
			Group:    corev1.SchemeGroupVersion.Group,
			Version:  corev1.SchemeGroupVersion.Version,
			Resource: "secrets",
		}

		generatedSymmetricKey = []byte("some-neato-32-byte-generated-key")

		generatedSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: generatedSecretNamePrefix,
				Namespace:    generatedSecretNamespace,
			},
			Type: "secrets.pinniped.dev/symmetric",
			Data: map[string][]byte{
				"key": generatedSymmetricKey,
			},
		}
	)

	generatedSecretWithName := generatedSecret.DeepCopy()
	generatedSecretWithName.Name = generatedSecretName

	once := sync.Once{}

	tests := []struct {
		name         string
		storedSecret func(**corev1.Secret)
		generateKey  func() ([]byte, error)
		apiClient    func(*testing.T, *kubernetesfake.Clientset)
		wantError    string
		wantActions  []kubetesting.Action
	}{
		{
			name: "when the secrets does not exist, it gets generated",
			storedSecret: func(secret **corev1.Secret) {
				*secret = nil
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewCreateAction(secretsGVR, generatedSecretNamespace, generatedSecret),
			},
		},
		{
			name: "when a valid secret exists, nothing happens",
		},
		{
			name: "secret gets updated when the type is wrong",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Type = "wrong"
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
			},
		},
		{
			name: "secret gets updated when the key data does not exist",
			storedSecret: func(secret **corev1.Secret) {
				delete((*secret).Data, "key")
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
			},
		},
		{
			name: "secret gets updated when the key data is too short",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short")
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
			},
		},
		{
			name: "an error is returned when creating fails",
			storedSecret: func(secret **corev1.Secret) {
				*secret = nil
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("create", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewCreateAction(secretsGVR, generatedSecretNamespace, generatedSecret),
			},
			wantError: "failed to create/update secret some-namespace/some-name-abc123: some create error",
		},
		{
			name: "an error is returned when updating fails",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("update", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
			},
			wantError: "failed to create/update secret some-namespace/some-name-abc123: some update error",
		},
		{
			name: "an error is returned when getting fails",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
			},
			wantError: "failed to create/update secret some-namespace/some-name-abc123: failed to get secret: some get error",
		},
		{
			name: "the update is retried when it fails due to a conflict",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("update", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					var err error
					once.Do(func() {
						err = k8serrors.NewConflict(secretsGVR.GroupResource(), generatedSecretName, errors.New("some error"))
					})
					return true, nil, err
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewUpdateAction(secretsGVR, generatedSecretNamespace, generatedSecretWithName),
			},
		},
		{
			name: "upon updating we discover that a valid secret exists",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, generatedSecretWithName, nil
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
			},
		},
		{
			name: "upon updating we discover that the secret has been deleted",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serrors.NewNotFound(secretsGVR.GroupResource(), generatedSecretName)
				})
				client.PrependReactor("create", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, nil
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewCreateAction(secretsGVR, generatedSecretNamespace, generatedSecret),
			},
		},
		{
			name: "upon updating we discover that the secret has been deleted and our create fails",
			storedSecret: func(secret **corev1.Secret) {
				(*secret).Data["key"] = []byte("too short") // force updating
			},
			apiClient: func(t *testing.T, client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serrors.NewNotFound(secretsGVR.GroupResource(), generatedSecretName)
				})
				client.PrependReactor("create", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretsGVR, generatedSecretNamespace, generatedSecretName),
				kubetesting.NewCreateAction(secretsGVR, generatedSecretNamespace, generatedSecret),
			},
			wantError: "failed to create/update secret some-namespace/some-name-abc123: failed to create secret: some create error",
		},
		{
			name: "when generating the secret fails, we return an error",
			storedSecret: func(secret **corev1.Secret) {
				*secret = nil
			},
			generateKey: func() ([]byte, error) {
				return nil, errors.New("some generate error")
			},
			wantError: "failed to generate secret: some generate error",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// We cannot currently run this test in parallel since it uses the global generateKey function.

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			if test.generateKey != nil {
				generateKey = test.generateKey
			} else {
				generateKey = func() ([]byte, error) {
					return generatedSymmetricKey, nil
				}
			}

			apiClient := kubernetesfake.NewSimpleClientset()
			if test.apiClient != nil {
				test.apiClient(t, apiClient)
			}
			informerClient := kubernetesfake.NewSimpleClientset()

			storedSecret := generatedSecretWithName.DeepCopy()
			if test.storedSecret != nil {
				test.storedSecret(&storedSecret)
			}
			if storedSecret != nil {
				require.NoError(t, apiClient.Tracker().Add(storedSecret))
				require.NoError(t, informerClient.Tracker().Add(storedSecret))
			}

			informers := kubeinformers.NewSharedInformerFactory(informerClient, 0)
			secrets := informers.Core().V1().Secrets()

			c := New(generatedSecretNamePrefix, apiClient, secrets)

			// Must start informers before calling TestRunSynchronously().
			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, c)

			err := controllerlib.TestSync(t, c, controllerlib.Context{
				Context: ctx,
				Key: controllerlib.Key{
					Namespace: generatedSecretNamespace,
					Name:      generatedSecretName,
				},
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}

			if test.wantActions == nil {
				test.wantActions = []kubetesting.Action{}
			}
			require.Equal(t, test.wantActions, apiClient.Actions())
		})
	}
}
