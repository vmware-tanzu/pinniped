// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/library"
)

func runTestKubectlCommand(t *testing.T, args ...string) (string, string) {
	t.Helper()

	var lock sync.Mutex
	var stdOut, stdErr bytes.Buffer
	var err error
	start := time.Now()
	attempts := 0
	if !assert.Eventually(t, func() bool {
		lock.Lock()
		defer lock.Unlock()
		attempts++
		stdOut.Reset()
		stdErr.Reset()
		cmd := exec.Command("kubectl", args...)
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		err = cmd.Run()
		return err == nil
	},
		120*time.Second,
		200*time.Millisecond,
	) {
		lock.Lock()
		defer lock.Unlock()
		t.Logf(
			"never ran %q successfully even after %d attempts (%s)",
			"kubectl "+strings.Join(args, " "),
			attempts,
			time.Since(start).Round(time.Second),
		)
		t.Logf("last error: %v", err)
		t.Logf("stdout:\n%s\n", stdOut.String())
		t.Logf("stderr:\n%s\n", stdErr.String())
		t.FailNow()
	}
	return stdOut.String(), stdErr.String()
}

func requireCleanKubectlStderr(t *testing.T, stderr string) {
	// Every line must be empty or contain a known, innocuous warning.
	for _, line := range strings.Split(stderr, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "Throttling request took") {
			continue
		}
		if strings.Contains(line, "due to client-side throttling, not priority and fairness") {
			continue
		}
		require.Failf(t, "unexpected kubectl stderr", "kubectl produced unexpected stderr:\n%s\n\n", stderr)
		return
	}
}

func TestGetPinnipedCategory(t *testing.T) {
	env := library.IntegrationEnv(t)
	dotSuffix := "." + env.APIGroupSuffix

	t.Run("category, no special params", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "pinniped", "-A")
		requireCleanKubectlStderr(t, stderr)
		require.NotContains(t, stdout, "MethodNotAllowed")
		require.Contains(t, stdout, dotSuffix)
	})

	t.Run("category, table params", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "pinniped", "-A", "-o", "wide", "-v", "10")
		require.NotContains(t, stdout, "MethodNotAllowed")
		require.Contains(t, stdout, dotSuffix)
		require.Contains(t, stderr, `"kind":"Table"`)
		require.Contains(t, stderr, `"resourceVersion":"0"`)
		require.Contains(t, stderr, `/v1alpha1/tokencredentialrequests`)
		require.Contains(t, stderr, `/v1alpha1/whoamirequests`)
	})

	t.Run("list, no special params", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "tokencredentialrequests.login.concierge"+dotSuffix, "-A")
		require.Empty(t, stdout)
		require.NotContains(t, stderr, "MethodNotAllowed")
		require.Contains(t, stderr, `No resources found`)
	})

	t.Run("list, table params", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "tokencredentialrequests.login.concierge"+dotSuffix, "-A", "-o", "wide", "-v", "10")
		require.Empty(t, stdout)
		require.NotContains(t, stderr, "MethodNotAllowed")
		require.Contains(t, stderr, `"kind":"Table"`)
		require.Contains(t, stderr, `"resourceVersion":"0"`)
	})

	t.Run("raw request to see body, token cred", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "--raw", "/apis/login.concierge"+dotSuffix+"/v1alpha1/tokencredentialrequests")
		require.NotContains(t, stdout, "MethodNotAllowed")
		require.Contains(t, stdout, `{"kind":"TokenCredentialRequestList","apiVersion":"login.concierge`+
			dotSuffix+`/v1alpha1","metadata":{"resourceVersion":"0"},"items":[]}`)
		requireCleanKubectlStderr(t, stderr)
	})

	t.Run("raw request to see body, whoami", func(t *testing.T) {
		t.Parallel()
		stdout, stderr := runTestKubectlCommand(t, "get", "--raw", "/apis/identity.concierge"+dotSuffix+"/v1alpha1/whoamirequests")
		require.NotContains(t, stdout, "MethodNotAllowed")
		require.Contains(t, stdout, `{"kind":"WhoAmIRequestList","apiVersion":"identity.concierge`+
			dotSuffix+`/v1alpha1","metadata":{"resourceVersion":"0"},"items":[]}`)
		requireCleanKubectlStderr(t, stderr)
	})
}
