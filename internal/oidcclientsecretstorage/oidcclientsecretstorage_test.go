// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/testutil"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name       string
		uid        types.UID
		secret     *corev1.Secret
		wantRV     string
		wantHashes []string
		wantErr    string
	}{
		{
			name: "happy path",
			uid:  types.UID("some-example-uid1"),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace:       "some-namespace",
					UID:             "",
					ResourceVersion: "123",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data": []byte(`{
						"hashes": ["foo", "bar"],
						"version": "1"
					}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantRV:     "123",
			wantHashes: []string{"foo", "bar"},
		},
		{
			name: "incorrect storage version: Data.pinniped-storage-version does not match crud storage version value",
			uid:  types.UID("some-example-uid1"),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace:       "some-namespace",
					UID:             "",
					ResourceVersion: "123",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data": []byte(`{
						"hashes": ["orcs", "goblins"],
						"version": "1"
					}`),
					"pinniped-storage-version": []byte("9999999999"),
				},
			},
			wantRV:     "",
			wantHashes: []string(nil),
			wantErr:    "failed to get client secret for uid some-example-uid1: error during get for signature c29tZS1leGFtcGxlLXVpZDE: secret storage data has incorrect version",
		},
		{
			name: "incorrect storage version: Data.pinniped-storage-data.version does not match package const oidcClientSecretStorageVersion",
			uid:  types.UID("some-example-uid1"),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace:       "some-namespace",
					UID:             "",
					ResourceVersion: "123",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data": []byte(`{
						"hashes": ["orcs", "goblins"],
						"version": "9999999999"
					}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantRV:     "",
			wantHashes: []string(nil),
			wantErr:    "OIDC client secret storage data has wrong version: OIDC client secret storage has version 9999999999 instead of 1",
		}, {
			name:       "not found",
			uid:        types.UID("some-example-uid1"),
			secret:     nil,
			wantRV:     "",
			wantHashes: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kubeClient := fake.NewSimpleClientset()
			if tt.secret != nil {
				require.NoError(t, kubeClient.Tracker().Add(tt.secret))
			}
			subject := New(kubeClient.CoreV1().Secrets("some-namespace"))
			rv, secretHashes, err := subject.Get(context.Background(), tt.uid)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
			require.Equal(t, tt.wantRV, rv)
			require.Equal(t, tt.wantHashes, secretHashes)
		})
	}
}

func TestSet(t *testing.T) {
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}
	namespace := "some-namespace"
	tests := []struct {
		name           string
		rv             string
		oidcClientName string
		oidcClientUID  types.UID
		hashes         []string
		seedSecret     *corev1.Secret
		addReactors    func(*fake.Clientset)
		wantErr        string
		wantActions    []coretesting.Action
	}{
		{
			name:           "happy path: new secret",
			oidcClientName: "some-client",
			oidcClientUID:  types.UID("some-example-uid1"),
			hashes:         []string{"foo"},
			seedSecret:     nil,
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "oidc-client-secret",
						},
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
							Kind:       "OIDCClient",
							Name:       "some-client",
							UID:        "some-example-uid1",
						}},
					},
					Type: "storage.pinniped.dev/oidc-client-secret",
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"hashes":["foo"],"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
				}),
			},
		},
		{
			name:           "happy path: update existing secret and maintains existing owner reference",
			rv:             "9999",
			oidcClientName: "some-client",
			oidcClientUID:  types.UID("some-example-uid1"),
			hashes:         []string{"foo", "bar"},
			seedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace: namespace,
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
					ResourceVersion: "9999",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
						Kind:       "OIDCClient",
						Name:       "some-client",
						UID:        "some-example-uid1",
					}},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["foo"],"version":"1"}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq"),
				coretesting.NewUpdateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "oidc-client-secret",
						},
						ResourceVersion: "9999",
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
							Kind:       "OIDCClient",
							Name:       "some-client",
							UID:        "some-example-uid1",
						}},
					},
					Type: "storage.pinniped.dev/oidc-client-secret",
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"hashes":["foo","bar"],"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
				}),
			},
		},
		{
			name:           "failed to create client secret",
			oidcClientName: "some-client",
			oidcClientUID:  types.UID("some-example-uid1"),
			hashes:         []string{"foo", "bar"},
			addReactors: func(clientSet *fake.Clientset) {
				clientSet.PrependReactor("create", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "oidc-client-secret",
						},
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
							Kind:       "OIDCClient",
							Name:       "some-client",
							UID:        "some-example-uid1",
						}},
					},
					Type: "storage.pinniped.dev/oidc-client-secret",
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"hashes":["foo","bar"],"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
				}),
			},
			wantErr: "failed to create client secret for uid some-example-uid1: failed to create oidc-client-secret for signature c29tZS1leGFtcGxlLXVpZDE: some create error",
		},
		{
			name:           "conflict: editing wrong resource version",
			rv:             "22",
			oidcClientName: "some-client",
			oidcClientUID:  types.UID("some-example-uid1"),
			hashes:         []string{"foo", "bar"},
			seedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace: namespace,
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
					ResourceVersion: "23",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
						Kind:       "OIDCClient",
						Name:       "some-client",
						UID:        "some-example-uid1",
					}},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["foo"],"version":"1"}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq"),
			},
			wantErr: "failed to update client secret for uid some-example-uid1: Operation cannot be fulfilled on Secret \"pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq\": resource version 23 does not match expected value: 22",
		},
		{
			name:           "failed to update",
			rv:             "23",
			oidcClientName: "some-client",
			oidcClientUID:  types.UID("some-example-uid1"),
			hashes:         []string{"foo", "bar"},
			seedSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace: namespace,
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
					ResourceVersion: "23",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
						Kind:       "OIDCClient",
						Name:       "some-client",
						UID:        "some-example-uid1",
					}},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["foo"],"version":"1"}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			addReactors: func(clientSet *fake.Clientset) {
				clientSet.PrependReactor("update", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq"),
				coretesting.NewUpdateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "oidc-client-secret",
						},
						ResourceVersion: "23",
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: "config.supervisor.pinniped.dev/v1alpha1",
							Kind:       "OIDCClient",
							Name:       "some-client",
							UID:        "some-example-uid1",
						}},
					},
					Type: "storage.pinniped.dev/oidc-client-secret",
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"hashes":["foo","bar"],"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
				}),
			},
			wantErr: "failed to update client secret for uid some-example-uid1: failed to update oidc-client-secret for signature c29tZS1leGFtcGxlLXVpZDE at resource version 23: some update error",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kubeClient := fake.NewSimpleClientset()
			if tt.seedSecret != nil {
				require.NoError(t, kubeClient.Tracker().Add(tt.seedSecret))
			}
			if tt.addReactors != nil {
				tt.addReactors(kubeClient)
			}
			subject := New(kubeClient.CoreV1().Secrets("some-namespace"))
			err := subject.Set(
				context.Background(),
				tt.rv,
				tt.oidcClientName,
				tt.oidcClientUID,
				tt.hashes,
			)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}

			require.Equal(t, tt.wantActions, kubeClient.Actions())
		})
	}
}

func TestGetStorageSecret(t *testing.T) {
	tests := []struct {
		name       string
		uid        types.UID
		secret     *corev1.Secret
		wantSecret *corev1.Secret
		wantErr    string
	}{
		{
			name: "happy path",
			uid:  types.UID("some-example-uid1"),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"foo": []byte("bar"),
				},
			},
			wantSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
					Namespace: "some-namespace",
				},
				Data: map[string][]byte{
					"foo": []byte("bar"),
				},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeClient := fake.NewSimpleClientset()
			require.NoError(t, kubeClient.Tracker().Add(tt.secret))
			subject := New(kubeClient.CoreV1().Secrets("some-namespace"))

			secret, err := subject.GetStorageSecret(context.Background(), tt.uid)
			require.Equal(t, tt.wantSecret, secret)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestGetName(t *testing.T) {
	// Note that GetName() should not depend on the constructor params, to make it easier to use in various contexts.
	subject := New(nil)

	require.Equal(t,
		"pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqyq",
		subject.GetName("some-example-uid1"))

	require.Equal(t,
		"pinniped-storage-oidc-client-secret-onxw2zjnmv4gc3lqnrss25ljmqza",
		subject.GetName("some-example-uid2"))
}

func TestReadFromSecret(t *testing.T) {
	tests := []struct {
		name       string
		secret     *corev1.Secret
		wantHashes []string
		wantErr    string
	}{
		{
			name: "happy path",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["first-hash","second-hash"],"version":"1"}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
			},
			wantHashes: []string{"first-hash", "second-hash"},
		},
		{
			name: "wrong secret type",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["first-hash","second-hash"],"version":"1"}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/not-oidc-client-secret",
			},
			wantErr: "secret storage data has incorrect type: storage.pinniped.dev/not-oidc-client-secret must equal storage.pinniped.dev/oidc-client-secret",
		},
		{
			name: "wrong stored StoredClientSecret version",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["first-hash","second-hash"],"version":"wrong-version-here"}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
			},
			wantErr: "OIDC client secret storage data has wrong version: OIDC client secret storage has version wrong-version-here instead of 1",
		},
		{
			name: "wrong storage version",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-oidc-client-secret-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "oidc-client-secret",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"hashes":["first-hash","second-hash"],"version":"1"}`),
					"pinniped-storage-version": []byte("wrong-version-here"),
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
			},
			wantErr: "secret storage data has incorrect version",
		},
		{
			name: "OIDCClientSecretStorageSecretForUID() test helper generates readable format, to ensure that test helpers are kept up to date",
			secret: testutil.OIDCClientSecretStorageSecretForUID(t,
				"some-namespace", "some-uid", []string{"first-hash", "second-hash"},
			),
			wantHashes: []string{"first-hash", "second-hash"},
		},
		{
			name: "OIDCClientSecretStorageSecretWithoutName() test helper generates readable format, to ensure that test helpers are kept up to date",
			secret: testutil.OIDCClientSecretStorageSecretWithoutName(t,
				"some-namespace", []string{"first-hash", "second-hash"},
			),
			wantHashes: []string{"first-hash", "second-hash"},
		},
		{
			name:    "OIDCClientSecretStorageSecretForUIDWithWrongVersion() test helper generates readable format, to ensure that test helpers are kept up to date",
			secret:  testutil.OIDCClientSecretStorageSecretForUIDWithWrongVersion(t, "some-namespace", "some-uid"),
			wantErr: "OIDC client secret storage data has wrong version: OIDC client secret storage has version wrong-version instead of 1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hashes, err := ReadFromSecret(tt.secret)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.wantHashes, hashes)
			} else {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, hashes)
			}
		})
	}
}
