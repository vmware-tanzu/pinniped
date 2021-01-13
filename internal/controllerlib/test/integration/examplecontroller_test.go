// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/internal/controllerlib/test/integration/examplecontroller/api"
	examplestart "go.pinniped.dev/internal/controllerlib/test/integration/examplecontroller/starter"
	"go.pinniped.dev/test/library"
)

func TestExampleController(t *testing.T) {
	library.SkipUnlessIntegration(t)

	config := library.NewClientConfig(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secretData := "super-secret-data-1"

	err := examplestart.StartExampleController(ctx, config, secretData)
	require.NoError(t, err)

	client, err := kubernetes.NewForConfig(config)
	require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")

	namespaces := client.CoreV1().Namespaces()

	namespace, err := namespaces.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "example-controller-test-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	defer func() {
		deleteErr := namespaces.Delete(context.Background(), namespace.Name, metav1.DeleteOptions{})
		require.NoError(t, deleteErr)
	}()

	services := client.CoreV1().Services(namespace.Name)
	secrets := client.CoreV1().Secrets(namespace.Name)

	secretsWatch, err := secrets.Watch(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	defer secretsWatch.Stop()

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "example-service-test",
			Annotations: map[string]string{
				api.SecretNameAnnotation: "example-secret-name",
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port: 443,
				},
			},
		},
	}
	_, err = services.Create(ctx, service, metav1.CreateOptions{})
	require.NoError(t, err)

	timeout := time.After(10 * time.Second)
done:
	for {
		select {
		case event := <-secretsWatch.ResultChan():
			if event.Type != watch.Added {
				continue
			}
			secret, ok := event.Object.(*corev1.Secret)
			if !ok {
				continue
			}
			if secret.Name != service.Annotations[api.SecretNameAnnotation] {
				continue
			}

			expectedData := map[string][]byte{
				api.SecretDataKey: []byte(secretData),
			}
			require.Equal(t, expectedData, secret.Data, "expected to see new secret data: %s", library.Sdump(secret))
			break done // immediately stop consuming events because we want to check for updated events below

		case <-timeout:
			t.Fatal("timed out waiting to see new secret")
		}
	}

	// shutdown the controllers so we can change the secret data
	cancel()
	time.Sleep(5 * time.Second) // wait a bit for the controllers to shut down

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	secretData2 := "super-secret-data-2"

	err = examplestart.StartExampleController(ctx, config, secretData2)
	require.NoError(t, err)

	timeout = time.After(10 * time.Second)
done2:
	for {
		select {
		case event := <-secretsWatch.ResultChan():
			if event.Type != watch.Modified {
				continue
			}
			secret, ok := event.Object.(*corev1.Secret)
			if !ok {
				continue
			}
			if secret.Name != service.Annotations[api.SecretNameAnnotation] {
				continue
			}

			expectedData := map[string][]byte{
				api.SecretDataKey: []byte(secretData2),
			}
			require.Equal(t, expectedData, secret.Data, "expected to see updated secret data: %s", library.Sdump(secret))
			break done2 // immediately stop consuming events because we want to check for hot loops below

		case <-timeout:
			t.Fatal("timed out waiting to see updated secret")
		}
	}

	timeout = time.After(5 * time.Second)
done3:
	for {
		select {
		case event := <-secretsWatch.ResultChan():
			secret, ok := event.Object.(*corev1.Secret)
			if !ok {
				continue
			}
			if secret.Name != service.Annotations[api.SecretNameAnnotation] {
				continue
			}

			// this assumes that no other actor in the system is trying to mutate this secret
			t.Errorf("unexpected event seen for secret: %s", library.Sdump(event))

		case <-timeout:
			break done3 // we saw no events matching our secret meaning that we are not hot looping
		}
	}
}
