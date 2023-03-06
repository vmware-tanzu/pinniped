// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build go1.20

package tlsassertions

func GetTlsErrorPrefix() string {
	return "tls: failed to verify certificate: "
}
