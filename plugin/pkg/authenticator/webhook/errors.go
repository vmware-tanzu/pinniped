/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import "fmt"

type unsupportedSchemeError struct {
	scheme string
}

func (e unsupportedSchemeError) Error() string {
	return fmt.Sprintf("unsupported scheme: %s", e.scheme)
}
