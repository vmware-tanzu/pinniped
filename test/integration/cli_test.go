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
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	// Create a test webhook configuration to use with the CLI.
	ctx, cancelFunc := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelFunc()

	idp := library.CreateTestWebhookIDP(ctx, t)

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
	kubeConfigYAML := runPinnipedCLI(t, pinnipedExe, env.TestUser.Token, env.Namespace, "webhook", idp.Name)

	// In addition to the client-go based testing below, also try the kubeconfig
	// with kubectl to validate that it works.
	adminClient := library.NewClientset(t)
	t.Run(
		"access as user with kubectl",
		accessAsUserWithKubectlTest(ctx, adminClient, kubeConfigYAML, env.TestUser.ExpectedUsername, env.Namespace),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group+" with kubectl",
			accessAsGroupWithKubectlTest(ctx, adminClient, kubeConfigYAML, group, env.Namespace),
		)
	}

	// Create Kubernetes client with kubeconfig from pinniped CLI.
	kubeClient := library.NewClientsetForKubeConfig(t, kubeConfigYAML)

	// Validate that we can auth to the API via our user.
	t.Run("access as user with client-go", accessAsUserTest(ctx, adminClient, env.TestUser.ExpectedUsername, kubeClient))
	for _, group := range env.TestUser.ExpectedGroups {
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

func runPinnipedCLI(t *testing.T, pinnipedExe, token, namespaceName, idpType, idpName string) string {
	t.Helper()

	output, err := exec.Command(
		pinnipedExe,
		"get-kubeconfig",
		"--token", token,
		"--pinniped-namespace", namespaceName,
		"--idp-type", idpType,
		"--idp-name", idpName,
	).CombinedOutput()
	require.NoError(t, err, string(output))

	return string(output)
}
