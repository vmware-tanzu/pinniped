// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ClusterCredential is a credential (token or certificate) which is valid on the Kubernetes cluster.
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
