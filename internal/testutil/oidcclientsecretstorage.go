// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"encoding/base32"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func secretNameForUID(uid string) string {
	// See GetName() in OIDCClientSecretStorage for how the production code determines the Secret name.
	// This test helper is intended to choose the same name.
	return "pinniped-storage-oidc-client-secret-" +
		strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(uid)))
}

func OIDCClientSecretStorageSecretWithoutName(t *testing.T, namespace string, hashes []string) *corev1.Secret {
	hashesJSON, err := json.Marshal(hashes)
	require.NoError(t, err) // this shouldn't really happen since we can always encode a slice of strings

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Labels:    map[string]string{"storage.pinniped.dev/type": "oidc-client-secret"},
		},
		Type: "storage.pinniped.dev/oidc-client-secret",
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"version":"1","hashes":` + string(hashesJSON) + `}`),
			"pinniped-storage-version": []byte("1"),
		},
	}
}

func OIDCClientSecretStorageSecretForUID(t *testing.T, namespace string, oidcClientUID string, hashes []string) *corev1.Secret {
	secret := OIDCClientSecretStorageSecretWithoutName(t, namespace, hashes)
	secret.Name = secretNameForUID(oidcClientUID)
	return secret
}

func OIDCClientSecretStorageSecretForUIDWithWrongVersion(t *testing.T, namespace string, oidcClientUID string) *corev1.Secret {
	secret := OIDCClientSecretStorageSecretForUID(t, namespace, oidcClientUID, []string{})
	secret.Data["pinniped-storage-data"] = []byte(`{"version":"wrong-version","hashes":[]}`)
	return secret
}
