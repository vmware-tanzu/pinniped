// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"strings"
)

func TruncateMostLongErr(err error) string {
	const max = 300
	msg := err.Error()

	// always log oidc and x509 errors completely
	if len(msg) <= max || strings.Contains(msg, "oidc:") || strings.Contains(msg, "x509:") {
		return msg
	}

	return msg[:max] + fmt.Sprintf(" [truncated %d chars]", len(msg)-max)
}
