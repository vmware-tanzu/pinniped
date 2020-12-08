// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authenticator contains helper code for dealing with *Authenticator CRDs.
package authenticator

import (
	"encoding/base64"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
)

// CABundle returns a PEM-encoded CA bundle from the provided spec. If the provided spec is nil, a
// nil CA bundle will be returned. If the provided spec contains a CA bundle that is not properly
// encoded, an error will be returned.
func CABundle(spec *auth1alpha1.TLSSpec) ([]byte, error) {
	if spec == nil {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(spec.CertificateAuthorityData)
}
