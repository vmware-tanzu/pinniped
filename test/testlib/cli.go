// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil"
)

//nolint:gochecknoglobals
var pinnipedCLIBinaryCache struct {
	buf   []byte
	mutex sync.Mutex
}

// PinnipedCLIPath returns the path to the Pinniped CLI binary, built on demand and cached between tests.
func PinnipedCLIPath(t *testing.T) string {
	t.Helper()

	// Allow a pre-built binary passed in via $PINNIPED_TEST_CLI. This is how our tests run in CI for efficiency.
	if ext, ok := os.LookupEnv("PINNIPED_TEST_CLI"); ok {
		t.Log("using externally provided pinniped CLI binary")
		return ext
	}

	pinnipedCLIBinaryCache.mutex.Lock()
	defer pinnipedCLIBinaryCache.mutex.Unlock()
	path := filepath.Join(testutil.TempDir(t), "pinniped")
	if pinnipedCLIBinaryCache.buf != nil {
		t.Log("using previously built pinniped CLI binary")
		//nolint:gosec // this is test code.
		require.NoError(t, os.WriteFile(path, pinnipedCLIBinaryCache.buf, 0500))
		return path
	}

	t.Log("building pinniped CLI binary")
	start := time.Now()
	output, err := exec.Command("go", "build", "-o", path, "go.pinniped.dev/cmd/pinniped").CombinedOutput()
	require.NoError(t, err, string(output))
	t.Logf("built CLI binary in %s", time.Since(start).Round(time.Millisecond))

	// Fill our cache so we don't have to do this again.
	pinnipedCLIBinaryCache.buf, err = os.ReadFile(path)
	require.NoError(t, err, string(output))

	return path
}
