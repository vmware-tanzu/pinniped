// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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

	"go.pinniped.dev/test/library"
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

	// Remove all Pinniped environment variables for the remainder of this test
	// because some of their names clash with the env vars expected by our
	// kubectl exec plugin. We would like this test to prove that the exec
	// plugin receives all of the necessary env vars via the auto-generated
	// kubeconfig from the Pinniped CLI.
	initialEnvVars := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		name := pair[0]
		value := pair[1]
		if strings.HasPrefix(name, "PINNIPED_") {
			initialEnvVars[name] = value
			err := os.Unsetenv(name)
			require.NoError(t, err)
		}
	}
	// Put them back for other tests to use after this one
	t.Cleanup(func() {
		for k, v := range initialEnvVars {
			err := os.Setenv(k, v)
			require.NoError(t, err)
		}
	})

	// Build pinniped CLI.
	pinnipedExe, cleanupFunc := buildPinnipedCLI(t)
	defer cleanupFunc()

	// Run pinniped CLI to get kubeconfig.
	kubeConfigYAML := runPinnipedCLI(t, pinnipedExe, token, namespaceName)

	adminClient := library.NewClientset(t)
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*3)
	defer cancelFunc()

	// In addition to the client-go based testing below, also try the kubeconfig
	// with kubectl to validate that it works.
	t.Run(
		"access as user with kubectl",
		accessAsUserWithKubectlTest(ctx, adminClient, kubeConfigYAML, testUsername, namespaceName),
	)
	for _, group := range expectedTestUserGroups {
		group := group
		t.Run(
			"access as group "+group+" with kubectl",
			accessAsGroupWithKubectlTest(ctx, adminClient, kubeConfigYAML, group, namespaceName),
		)
	}

	// Create Kubernetes client with kubeconfig from pinniped CLI.
	kubeClient := library.NewClientsetForKubeConfig(t, kubeConfigYAML)

	// Validate that we can auth to the API via our user.
	t.Run("access as user with client-go", accessAsUserTest(ctx, adminClient, testUsername, kubeClient))
	for _, group := range expectedTestUserGroups {
		group := group
		t.Run("access as group "+group+" with client-go", accessAsGroupTest(ctx, adminClient, group, kubeClient))
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
		"go.pinniped.dev/cmd/pinniped",
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
