// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// ErrorWriter implements io.Writer by returning a fixed error.
type ErrorWriter struct {
	ReturnError error
}

var _ io.Writer = &ErrorWriter{}

func (e *ErrorWriter) Write([]byte) (int, error) { return 0, e.ReturnError }

func WriteStringToTempFile(t *testing.T, filename string, fileBody string) *os.File {
	t.Helper()
	f, err := ioutil.TempFile("", filename)
	require.NoError(t, err)
	deferMe := func() {
		err := os.Remove(f.Name())
		require.NoError(t, err)
	}
	t.Cleanup(deferMe)
	_, err = f.WriteString(fileBody)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	return f
}
