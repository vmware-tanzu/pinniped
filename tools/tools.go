// +build tools

/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package tools exists to work around a Go modules oddity and depend on some tool versions.
package tools

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)
