// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conciergetestutil

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
)

func TLSSpecFromTLSConfig(tls *tls.Config) *authenticationv1alpha1.TLSSpec {
	pemData := make([]byte, 0)
	for _, certificate := range tls.Certificates {
		// this is the public part of the certificate, the private is the certificate.PrivateKey
		for _, reallyCertificate := range certificate.Certificate {
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: reallyCertificate,
			})...)
		}
	}
	return &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(pemData),
	}
}
