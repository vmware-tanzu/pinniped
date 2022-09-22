// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ClusterCredential is the cluster-specific credential returned on a successful credential request. It
// contains either a valid bearer token or a valid TLS certificate and corresponding private key for the cluster.
type ClusterCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time

	// Token is a bearer token used by the client for request authentication.
	Token string

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string

	// PEM-encoded private key for the above certificate.
	ClientKeyData string
}
