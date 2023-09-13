// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package csp defines helpers related to HTML Content Security Policies.
package csp

import (
	"crypto/sha256"
	"encoding/base64"
)

func Hash(s string) string {
	hashBytes := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(hashBytes[:])
}
