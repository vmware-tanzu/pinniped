// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"runtime"
)

func X509UntrustedCertError(commonName string) string {
	if runtime.GOOS == "darwin" {
		// Golang use's macos' x509 verification APIs on darwin.
		// This output slightly different error messages than golang's
		// own x509 verification.
		return fmt.Sprintf(`x509: “%s” certificate is not trusted`, commonName)
	}
	return `x509: certificate signed by unknown authority`
}
