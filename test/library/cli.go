// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil"
)

//nolint: gochecknoglobals
var pinnipedCLIBinaryCache struct {
	buf   []byte
	mutex sync.Mutex
}

// PinnipedCLIPath returns the path to the Pinniped CLI binary, built on demand and cached between tests.
func PinnipedCLIPath(t *testing.T) string {
	t.Helper()
	pinnipedCLIBinaryCache.mutex.Lock()
	defer pinnipedCLIBinaryCache.mutex.Unlock()
	path := filepath.Join(testutil.TempDir(t), "pinniped")
	if pinnipedCLIBinaryCache.buf != nil {
		t.Log("using previously built pinniped CLI binary")
		require.NoError(t, ioutil.WriteFile(path, pinnipedCLIBinaryCache.buf, 0500))
		return path
	}

	t.Log("building pinniped CLI binary")
	output, err := exec.Command("go", "build", "-o", path, "go.pinniped.dev/cmd/pinniped").CombinedOutput()
	require.NoError(t, err, string(output))

	// Fill our cache so we don't have to do this again.
	pinnipedCLIBinaryCache.buf, err = ioutil.ReadFile(path)
	require.NoError(t, err, string(output))

	return path
}
