// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/pinniped/test/library"
)

// Smoke test to see if the kubeconfig works and the cluster is reachable.
func TestGetNodes(t *testing.T) {
	library.SkipUnlessIntegration(t)
	cmd := exec.Command("kubectl", "get", "nodes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)
}
