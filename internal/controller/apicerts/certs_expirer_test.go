// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestExpirerControllerFilters(t *testing.T) {
	t.Parallel()

	const certsSecretResourceName = "some-resource-name"

	tests := []struct {
		name      string
		namespace string
		secret    corev1.Secret
		want      bool
	}{
		{
			name:      "good name, good namespace",
			namespace: "good-namespace",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certsSecretResourceName,
					Namespace: "good-namespace",
				},
			},
			want: true,
		},
		{
			name:      "bad name, good namespace",
			namespace: "good-namespacee",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bad-name",
					Namespace: "good-namespace",
				},
			},
			want: false,
		},
		{
			name:      "good name, bad namespace",
			namespace: "good-namespacee",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      certsSecretResourceName,
					Namespace: "bad-namespace",
				},
			},
			want: false,
		},
		{
			name:      "bad name, bad namespace",
			namespace: "good-namespacee",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bad-name",
					Namespace: "bad-namespace",
				},
			},
			want: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name+"-"+test.namespace, func(t *testing.T) {
			t.Parallel()

			secretsInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewCertsExpirerController(
				test.namespace,
				certsSecretResourceName,
				nil, // k8sClient, not needed
				secretsInformer,
				withInformer.WithInformer,
				0,  // renewBefore, not needed
				"", // not needed
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretsInformer)
			require.Equal(t, test.want, filter.Add(&test.secret))
			require.Equal(t, test.want, filter.Update(&unrelated, &test.secret))
			require.Equal(t, test.want, filter.Update(&test.secret, &unrelated))
			require.Equal(t, test.want, filter.Delete(&test.secret))
		})
	}
}

func TestExpirerControllerSync(t *testing.T) {
	t.Parallel()

	const certsSecretResourceName = "some-resource-name"
	const fakeTestKey = "some-awesome-key"

	tests := []struct {
		name                string
		renewBefore         time.Duration
		fillSecretData      func(*testing.T, map[string][]byte)
		configKubeAPIClient func(*kubernetesfake.Clientset)
		wantDelete          bool
		wantError           string
	}{
		{
			name:       "secret does not exist",
			wantDelete: false,
		},
		{
			name:           "secret missing key",
			fillSecretData: func(t *testing.T, m map[string][]byte) {},
			wantDelete:     false,
			wantError:      `failed to get cert bounds for secret "some-resource-name" with key "some-awesome-key": failed to find certificate`,
		},
		{
			name:        "lifetime below threshold",
			renewBefore: 7 * time.Hour,
			fillSecretData: func(t *testing.T, m map[string][]byte) {
				certPEM, _, err := testutil.CreateCertificate(
					time.Now().Add(-5*time.Hour),
					time.Now().Add(5*time.Hour),
				)
				require.NoError(t, err)

				m[fakeTestKey] = certPEM
			},
			wantDelete: false,
		},
		{
			name:        "lifetime above threshold",
			renewBefore: 3 * time.Hour,
			fillSecretData: func(t *testing.T, m map[string][]byte) {
				certPEM, _, err := testutil.CreateCertificate(
					time.Now().Add(-5*time.Hour),
					time.Now().Add(5*time.Hour),
				)
				require.NoError(t, err)

				m[fakeTestKey] = certPEM
			},
			wantDelete: true,
		},
		{
			name:        "cert expired",
			renewBefore: 3 * time.Hour,
			fillSecretData: func(t *testing.T, m map[string][]byte) {
				certPEM, _, err := testutil.CreateCertificate(
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-1*time.Hour),
				)
				require.NoError(t, err)

				m[fakeTestKey] = certPEM
			},
			wantDelete: true,
		},
		{
			name:        "delete failure",
			renewBefore: 3 * time.Hour,
			fillSecretData: func(t *testing.T, m map[string][]byte) {
				certPEM, _, err := testutil.CreateCertificate(
					time.Now().Add(-5*time.Hour),
					time.Now().Add(5*time.Hour),
				)
				require.NoError(t, err)

				m[fakeTestKey] = certPEM
			},
			configKubeAPIClient: func(c *kubernetesfake.Clientset) {
				c.PrependReactor("delete", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("delete failed: some delete error")
				})
			},
			wantError: "delete failed: some delete error",
		},
		{
			name: "parse cert failure",
			fillSecretData: func(t *testing.T, m map[string][]byte) {
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				m[fakeTestKey], err = x509.MarshalPKCS8PrivateKey(privateKey)
				require.NoError(t, err)
			},
			wantDelete: false,
			wantError:  `failed to get cert bounds for secret "some-resource-name" with key "some-awesome-key": failed to decode certificate PEM`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			kubeAPIClient := kubernetesfake.NewSimpleClientset()
			if test.configKubeAPIClient != nil {
				test.configKubeAPIClient(kubeAPIClient)
			}

			kubeInformerClient := kubernetesfake.NewSimpleClientset()
			name := certsSecretResourceName
			namespace := "some-namespace"
			if test.fillSecretData != nil {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Data: map[string][]byte{},
				}
				test.fillSecretData(t, secret.Data)

				require.NoError(t, kubeAPIClient.Tracker().Add(secret))
				require.NoError(t, kubeInformerClient.Tracker().Add(secret))
			}

			kubeInformers := kubeinformers.NewSharedInformerFactory(
				kubeInformerClient,
				0,
			)

			c := NewCertsExpirerController(
				namespace,
				certsSecretResourceName,
				kubeAPIClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				test.renewBefore,
				fakeTestKey,
			)

			// Must start informers before calling TestRunSynchronously().
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, c)

			err := controllerlib.TestSync(t, c, controllerlib.Context{
				Context: ctx,
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.NoError(t, err)

			exActions := []kubetesting.Action{}
			if test.wantDelete {
				exActions = append(
					exActions,
					kubetesting.NewDeleteAction(
						schema.GroupVersionResource{
							Group:    "",
							Version:  "v1",
							Resource: "secrets",
						},
						namespace,
						name,
					),
				)
			}
			acActions := kubeAPIClient.Actions()
			require.Equal(t, exActions, acActions)
		})
	}
}
