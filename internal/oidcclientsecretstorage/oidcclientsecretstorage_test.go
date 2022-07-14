// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/testutil"
)

func TestGetName(t *testing.T) {
	// Note that GetName() should not depend on the constructor params, to make it easier to use in various contexts.
	subject := New(nil, nil)

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
		wantStored *StoredClientSecret
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
			wantStored: &StoredClientSecret{
				Version:      "1",
				SecretHashes: []string{"first-hash", "second-hash"},
			},
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
			wantStored: &StoredClientSecret{
				Version:      "1",
				SecretHashes: []string{"first-hash", "second-hash"},
			},
		},
		{
			name: "OIDCClientSecretStorageSecretWithoutName() test helper generates readable format, to ensure that test helpers are kept up to date",
			secret: testutil.OIDCClientSecretStorageSecretWithoutName(t,
				"some-namespace", []string{"first-hash", "second-hash"},
			),
			wantStored: &StoredClientSecret{
				Version:      "1",
				SecretHashes: []string{"first-hash", "second-hash"},
			},
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
			session, err := ReadFromSecret(tt.secret)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.wantStored, session)
			} else {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, session)
			}
		})
	}
}
