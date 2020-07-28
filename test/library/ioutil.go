/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import "io"

// ErrorWriter implements io.Writer by returning a fixed error.
type ErrorWriter struct {
	ReturnError error
}

var _ io.Writer = &ErrorWriter{}

func (e *ErrorWriter) Write([]byte) (int, error) { return 0, e.ReturnError }
