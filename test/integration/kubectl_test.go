/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestGetNodes(t *testing.T) {
	library.SkipUnlessIntegration(t)
	cmd := exec.Command("kubectl", "get", "nodes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)
}
