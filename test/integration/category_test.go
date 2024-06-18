// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/test/testlib"
)

func runTestKubectlCommand(t *testing.T, args ...string) (string, string) {
	t.Helper()
	var stdOut, stdErr bytes.Buffer
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		stdOut.Reset()
		stdErr.Reset()
		cmd := exec.Command("kubectl", args...)
		cmd.Stdout = &stdOut
		cmd.Stderr = &stdErr
		requireEventually.NoError(cmd.Run())
	}, 120*time.Second, 200*time.Millisecond)
	return stdOut.String(), stdErr.String()
}

func requireCleanKubectlStderr(t *testing.T, stderr string) {
	// Every line must be empty or contain a known, innocuous warning.
	for _, line := range strings.Split(stderr, "\n") {
		switch {
		case strings.TrimSpace(line) == "",
			strings.Contains(line, "Throttling request took"),
			strings.Contains(line, "due to client-side throttling, not priority and fairness"),
			strings.Contains(line, "the gcp auth plugin is deprecated in v1.22+, unavailable in "),
			strings.Contains(line, "To learn more, consult https://cloud.google.com/blog/products/containers-kubernetes/kubectl-auth-changes-in-gke"):
			// ignore these allowed stderr lines
		default:
			// anything else is a failure
			require.Failf(t, "unexpected kubectl stderr", "kubectl produced unexpected stderr:\n%s\n\n", stderr)
			return
		}
	}
}

func TestGetPinnipedCategory(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	dotSuffix := "." + env.APIGroupSuffix

	aggregatedAPIResources := []struct {
		metav1.GroupVersion
		ListKind string
		Resource string
	}{
		{
			GroupVersion: metav1.GroupVersion{
				Group:   "login.concierge" + dotSuffix,
				Version: "v1alpha1",
			},
			ListKind: "TokenCredentialRequestList",
			Resource: "tokencredentialrequests",
		},
		{
			GroupVersion: metav1.GroupVersion{
				Group:   "identity.concierge" + dotSuffix,
				Version: "v1alpha1",
			},
			ListKind: "WhoAmIRequestList",
			Resource: "whoamirequests",
		},
		{
			GroupVersion: metav1.GroupVersion{
				Group:   "clientsecret.supervisor" + dotSuffix,
				Version: "v1alpha1",
			},
			ListKind: "OIDCClientSecretRequestList",
			Resource: "oidcclientsecretrequests",
		},
	}

	t.Run("can kubectl get whole category as table", func(t *testing.T) {
		t.Parallel()

		stdout, stderr := runTestKubectlCommand(t, "get", "pinniped", "-A")
		requireCleanKubectlStderr(t, stderr)
		require.NotContains(t, stdout, "MethodNotAllowed")

		// The resulting table should include at least a CredentialIssuer.
		require.Contains(t, stdout, dotSuffix)
	})

	t.Run("can kubectl get each aggregated API as table, and listing these aggregated always results in an empty list", func(t *testing.T) {
		t.Parallel()

		for _, tt := range aggregatedAPIResources {
			t.Run(tt.Resource, func(t *testing.T) {
				t.Parallel()

				stdout, stderr := runTestKubectlCommand(t, "get", fmt.Sprintf("%s.%s", tt.Resource, tt.Group), "-A")
				require.Empty(t, stdout)

				require.NotContains(t, stderr, "MethodNotAllowed")
				require.Contains(t, stderr, `No resources found`)
			})
		}
	})

	t.Run("can kubectl get each aggregated API using raw request, and listing these aggregated always results in an empty list", func(t *testing.T) {
		t.Parallel()

		for _, tt := range aggregatedAPIResources {
			t.Run(tt.Resource, func(t *testing.T) {
				t.Parallel()

				stdout, stderr := runTestKubectlCommand(t, "get",
					"--raw", fmt.Sprintf("/apis/%s/%s/%s", tt.Group, tt.Version, tt.Resource))

				requireCleanKubectlStderr(t, stderr)
				require.NotContains(t, stdout, "MethodNotAllowed")

				require.Contains(t, stdout,
					fmt.Sprintf(`{"kind":"%s","apiVersion":"%s/%s","metadata":{"resourceVersion":"0"},"items":[]}`,
						tt.ListKind, tt.Group, tt.Version),
				)
			})
		}
	})
}
