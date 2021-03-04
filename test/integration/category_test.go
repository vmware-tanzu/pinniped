// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/library"
)

func TestGetPinnipedCategory(t *testing.T) {
	env := library.IntegrationEnv(t)
	dotSuffix := "." + env.APIGroupSuffix

	t.Run("category, no special params", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		var err error
		require.Eventuallyf(t, func() bool {
			cmd := exec.Command("kubectl", "get", "pinniped", "-A")
			cmd.Stdout = &stdOut
			cmd.Stderr = &stdErr
			err = cmd.Run()
			return err == nil
		},
			60*time.Second,
			1*time.Second,
			"never ran 'kubectl get pinniped -A' successfully:\n%s\n\n%s",
			stdErr.String(),
			stdOut.String(),
		)
		require.Empty(t, stdErr.String())
		require.NotContains(t, stdOut.String(), "MethodNotAllowed")
		require.Contains(t, stdOut.String(), dotSuffix)
	})

	t.Run("category, table params", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		cmd := exec.Command("kubectl", "get", "pinniped", "-A", "-o", "wide", "-v", "10")
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err := cmd.Run()
		require.NoError(t, err, stdErr.String(), stdOut.String())

		require.NotContains(t, stdOut.String(), "MethodNotAllowed")
		require.Contains(t, stdOut.String(), dotSuffix)

		require.Contains(t, stdErr.String(), `"kind":"Table"`)
		require.Contains(t, stdErr.String(), `"resourceVersion":"0"`)
		require.Contains(t, stdErr.String(), `/v1alpha1/tokencredentialrequests`)
		require.Contains(t, stdErr.String(), `/v1alpha1/whoamirequests`)
	})

	t.Run("list, no special params", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		//nolint: gosec  // input is part of test env
		cmd := exec.Command("kubectl", "get", "tokencredentialrequests.login.concierge"+dotSuffix, "-A")
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err := cmd.Run()
		require.NoError(t, err, stdErr.String(), stdOut.String())
		require.Empty(t, stdOut.String())

		require.NotContains(t, stdErr.String(), "MethodNotAllowed")
		require.Contains(t, stdErr.String(), `No resources found`)
	})

	t.Run("list, table params", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		//nolint: gosec  // input is part of test env
		cmd := exec.Command("kubectl", "get", "tokencredentialrequests.login.concierge"+dotSuffix, "-A", "-o", "wide", "-v", "10")
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err := cmd.Run()
		require.NoError(t, err, stdErr.String(), stdOut.String())
		require.Empty(t, stdOut.String())

		require.NotContains(t, stdErr.String(), "MethodNotAllowed")
		require.Contains(t, stdErr.String(), `"kind":"Table"`)
		require.Contains(t, stdErr.String(), `"resourceVersion":"0"`)
	})

	t.Run("raw request to see body, token cred", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		//nolint: gosec  // input is part of test env
		cmd := exec.Command("kubectl", "get", "--raw", "/apis/login.concierge"+dotSuffix+"/v1alpha1/tokencredentialrequests")
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err := cmd.Run()
		require.NoError(t, err, stdErr.String(), stdOut.String())
		require.Empty(t, stdErr.String())

		require.NotContains(t, stdOut.String(), "MethodNotAllowed")
		require.Contains(t, stdOut.String(), `{"kind":"TokenCredentialRequestList","apiVersion":"login.concierge`+
			dotSuffix+`/v1alpha1","metadata":{"resourceVersion":"0"},"items":[]}`)
	})

	t.Run("raw request to see body, whoami", func(t *testing.T) {
		var stdOut, stdErr bytes.Buffer

		//nolint: gosec  // input is part of test env
		cmd := exec.Command("kubectl", "get", "--raw", "/apis/identity.concierge"+dotSuffix+"/v1alpha1/whoamirequests")
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err := cmd.Run()
		require.NoError(t, err, stdErr.String(), stdOut.String())
		require.Empty(t, stdErr.String())

		require.NotContains(t, stdOut.String(), "MethodNotAllowed")
		require.Contains(t, stdOut.String(), `{"kind":"WhoAmIRequestList","apiVersion":"identity.concierge`+
			dotSuffix+`/v1alpha1","metadata":{"resourceVersion":"0"},"items":[]}`)
	})
}
