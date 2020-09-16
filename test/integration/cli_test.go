/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
package integration

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/pinniped/test/library"
)

func TestCLI(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)
	token := library.GetEnv(t, "PINNIPED_TEST_USER_TOKEN")
	namespaceName := library.GetEnv(t, "PINNIPED_NAMESPACE")
	testUsername := library.GetEnv(t, "PINNIPED_TEST_USER_USERNAME")
	expectedTestUserGroups := strings.Split(
		strings.ReplaceAll(library.GetEnv(t, "PINNIPED_TEST_USER_GROUPS"), " ", ""), ",",
	)

	// Build pinniped CLI.
	pinnipedExe, cleanupFunc := buildPinnipedCLI(t)
	defer cleanupFunc()

	// Run pinniped CLI to get kubeconfig.
	kubeConfig := runPinnipedCLI(t, pinnipedExe, token, namespaceName)

	// Create Kubernetes client with kubeconfig from pinniped CLI.
	kubeClient := library.NewClientsetForKubeConfig(t, kubeConfig)

	// Validate that we can auth to the API via our user.
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*3)
	defer cancelFunc()

	adminClient := library.NewClientset(t)

	t.Run("access as user", accessAsUserTest(ctx, adminClient, testUsername, kubeClient))
	for _, group := range expectedTestUserGroups {
		group := group
		t.Run(
			"access as group "+group,
			accessAsGroupTest(ctx, adminClient, group, kubeClient),
		)
	}
}

func buildPinnipedCLI(t *testing.T) (string, func()) {
	t.Helper()

	pinnipedExeDir, err := ioutil.TempDir("", "pinniped-cli-test-*")
	require.NoError(t, err)

	pinnipedExe := filepath.Join(pinnipedExeDir, "pinniped")
	output, err := exec.Command(
		"go",
		"build",
		"-o",
		pinnipedExe,
		"github.com/suzerain-io/pinniped/cmd/pinniped",
	).CombinedOutput()
	require.NoError(t, err, string(output))

	return pinnipedExe, func() {
		require.NoError(t, os.RemoveAll(pinnipedExeDir))
	}
}

func runPinnipedCLI(t *testing.T, pinnipedExe, token, namespaceName string) string {
	t.Helper()

	output, err := exec.Command(
		pinnipedExe,
		"get-kubeconfig",
		"--token", token,
		"--pinniped-namespace", namespaceName,
	).CombinedOutput()
	require.NoError(t, err, string(output))

	return string(output)
}
