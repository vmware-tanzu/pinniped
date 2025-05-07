// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	corev1 "k8s.io/api/core/v1"
)

type RetrieveFromSecretFunc func(secret *corev1.Secret) ([]byte, []byte)

func RetrieveCAFromSecret(secret *corev1.Secret) ([]byte, []byte) {
	if secret == nil {
		return nil, nil
	}

	return secret.Data[caCertificateSecretKey], secret.Data[caCertificatePrivateKeySecretKey]
}

func RetrieveCertificateFromSecret(secret *corev1.Secret) ([]byte, []byte) {
	if secret == nil {
		return nil, nil
	}

	return secret.Data[tlsCertificateChainSecretKey], secret.Data[tlsPrivateKeySecretKey]
}

// Ensure matching function signature at compile time.
var _ RetrieveFromSecretFunc = RetrieveCAFromSecret
var _ RetrieveFromSecretFunc = RetrieveCertificateFromSecret
