// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/sha256"
	"encoding/base64"
)

// SHA256 returns the base64 URL encoding of the SHA256 sum of the provided string.
func SHA256(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
