// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ClusterCredential is the cluster-specific credential returned on a successful credential request. It
// contains either a valid bearer token or a valid TLS certificate and corresponding private key for the cluster.
type ClusterCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time `json:"expirationTimestamp,omitempty"`

	// Token is a bearer token used by the client for request authentication.
	Token string `json:"token,omitempty"`

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string `json:"clientCertificateData,omitempty"`

	// PEM-encoded private key for the above certificate.
	ClientKeyData string `json:"clientKeyData,omitempty"`
}
