// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestRetrieveCAFromSecret(t *testing.T) {
	tests := []struct {
		name            string
		secret          *corev1.Secret
		wantCertificate []byte
		wantPrivateKey  []byte
	}{
		{
			name:   "nil input returns empty",
			secret: nil,
		},
		{
			name:   "empty secret returns empty",
			secret: &corev1.Secret{},
		},
		{
			name: "populated secret returns values",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"caCertificate":           []byte("foo"),
					"caCertificatePrivateKey": []byte("bar"),
					"baz":                     []byte("quz"),
				},
			},
			wantCertificate: []byte("foo"),
			wantPrivateKey:  []byte("bar"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualCert, actualKey := RetrieveCAFromSecret(test.secret)

			require.Equal(t, test.wantCertificate, actualCert)
			require.Equal(t, test.wantPrivateKey, actualKey)
		})
	}
}

func TestRetrieveCertificateFromSecret(t *testing.T) {
	tests := []struct {
		name            string
		secret          *corev1.Secret
		wantCertificate []byte
		wantPrivateKey  []byte
	}{
		{
			name:   "nil input returns empty",
			secret: nil,
		},
		{
			name:   "empty secret returns empty",
			secret: &corev1.Secret{},
		},
		{
			name: "populated secret returns values",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tlsCertificateChain": []byte("foo"),
					"tlsPrivateKey":       []byte("bar"),
					"baz":                 []byte("quz"),
				},
			},
			wantCertificate: []byte("foo"),
			wantPrivateKey:  []byte("bar"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualCert, actualKey := RetrieveCertificateFromSecret(test.secret)

			require.Equal(t, test.wantCertificate, actualCert)
			require.Equal(t, test.wantPrivateKey, actualKey)
		})
	}
}
