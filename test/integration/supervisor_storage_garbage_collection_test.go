// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/test/testlib"
)

func TestStorageGarbageCollection(t *testing.T) {
	// Run this test in parallel with the other integration tests because it does a lot of waiting
	// and will not impact other tests, or be impacted by other tests, when run in parallel.
	t.Parallel()

	env := testlib.IntegrationEnv(t)
	client := testlib.NewKubernetesClientset(t)
	secrets := client.CoreV1().Secrets(env.SupervisorNamespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secretAlreadyExpired := createSecret(ctx, t, secrets, "past", time.Now().Add(-time.Second))
	secretWhichWillExpireBeforeTheTestEnds := createSecret(ctx, t, secrets, "near-future", time.Now().Add(30*time.Second))
	secretNotYetExpired := createSecret(ctx, t, secrets, "far-future", time.Now().Add(10*time.Minute))

	// Start a background goroutine which will end as soon as the test ends.
	// Keep updating a secret which has the "storage.pinniped.dev/garbage-collect-after" annotation
	// in the same namespace just to get the controller to respond faster.
	// This is just a performance optimization to make this test pass faster because otherwise
	// this test has to wait ~3 minutes for the controller's next full-resync.
	stopCh := make(chan struct{})
	errCh := make(chan error)
	go updateSecretEveryTwoSeconds(stopCh, errCh, secrets, secretNotYetExpired)
	t.Cleanup(func() {
		close(stopCh)

		if updateErr := <-errCh; updateErr != nil {
			panic(updateErr)
		}
	})

	// Wait long enough for the next periodic sweep of the GC controller for the secrets to be deleted, which
	// is the worst-case length of time that we should ever need to wait. Because of the goroutine above,
	// in practice we should only need to wait about 30 seconds, which is the GC controller's self-imposed
	// rate throttling time period.
	slightlyLongerThanGCControllerFullResyncPeriod := 3*time.Minute + 30*time.Second
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		_, err := secrets.Get(ctx, secretAlreadyExpired.Name, metav1.GetOptions{})
		requireEventually.Truef(k8serrors.IsNotFound(err), "wanted a NotFound error but got %v", err)
	}, slightlyLongerThanGCControllerFullResyncPeriod, 250*time.Millisecond)

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		_, err := secrets.Get(ctx, secretWhichWillExpireBeforeTheTestEnds.Name, metav1.GetOptions{})
		requireEventually.Truef(k8serrors.IsNotFound(err), "wanted a NotFound error but got %v", err)
	}, slightlyLongerThanGCControllerFullResyncPeriod, 250*time.Millisecond)

	// The unexpired secret should not have been deleted within the timeframe of this test run.
	_, err := secrets.Get(ctx, secretNotYetExpired.Name, metav1.GetOptions{})
	require.NoError(t, err)
}

func updateSecretEveryTwoSeconds(stopCh chan struct{}, errCh chan error, secrets corev1client.SecretInterface, secret *v1.Secret) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var updateErr error
	defer func() {
		errCh <- updateErr
	}()

	i := 0
	for {
		select {
		case <-stopCh:
			// Got a signal, so stop running.
			return
		default:
			// Channel had no message, so keep running.
		}

		time.Sleep(2 * time.Second)

		i++
		secret.Data["foo"] = []byte(fmt.Sprintf("bar-%d", i))
		secret, updateErr = secrets.Update(ctx, secret, metav1.UpdateOptions{})

		switch {
		case updateErr == nil:
			// continue to next update

		case k8serrors.IsConflict(updateErr), k8serrors.IsNotFound(updateErr):
			select {
			case _, ok := <-stopCh:
				if !ok { // stopCh is closed meaning that test is already finished so these errors are expected
					updateErr = nil
				}
			default:
			}

			return // even if the error is expected, we must stop
		default:
			return // unexpected error
		}
	}
}

func createSecret(ctx context.Context, t *testing.T, secrets corev1client.SecretInterface, name string, expiresAt time.Time) *v1.Secret {
	secret, err := secrets.Create(ctx, newSecret("pinniped-storage-gc-integration-test-"+name+"-", expiresAt), metav1.CreateOptions{})
	require.NoError(t, err)

	// Make sure the Secret is deleted when the test ends.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := secrets.Delete(ctx, secret.Name, metav1.DeleteOptions{})
		notFound := k8serrors.IsNotFound(err)
		if !notFound {
			// it's okay if the Secret was already deleted, but other errors are cleanup failures
			require.NoError(t, err)
		}
	})

	return secret
}

func newSecret(namePrefix string, expiresAt time.Time) *v1.Secret {
	annotations := map[string]string{}
	if !expiresAt.Equal(time.Time{}) {
		// Mark the secret for garbage collection.
		annotations[crud.SecretLifetimeAnnotationKey] = expiresAt.UTC().Format(time.RFC3339)
	}
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: namePrefix,
			Annotations:  annotations,
		},
		Data: map[string][]byte{"some-key": []byte("fake-data")},
		Type: "storage.pinniped.dev/gc-test-integration-test", // the garbage collector controller doesn't care about the type
	}
}
