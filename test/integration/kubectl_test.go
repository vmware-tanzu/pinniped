/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetNodes(t *testing.T) {
	err := exec.Command("kubectl", "get", "nodes").Run()
	require.NoError(t, err)
}
