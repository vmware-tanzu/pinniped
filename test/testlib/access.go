// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	accessRetryInterval = 250 * time.Millisecond
	accessRetryTimeout  = 2 * time.Minute
)

// AccessAsUserTest runs a generic test in which a clientUnderTest operating with username
// testUsername tries to auth to the kube API (i.e., list namespaces).
//
// Use this function if you want to simply validate that a user can auth to the kube API after
// performing a Pinniped credential exchange.
func AccessAsUserTest(
	ctx context.Context,
	testUsername string,
	clientUnderTest kubernetes.Interface,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterUserCanViewEverythingRoleBinding(t, testUsername)

		// Use the client which is authenticated as the test user to list namespaces
		RequireEventually(t, func(requireEventually *require.Assertions) {
			resp, err := clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			requireEventually.NoError(err)
			requireEventually.NotNil(resp)
			requireEventually.NotEmpty(resp.Items)
		}, accessRetryTimeout, accessRetryInterval, "user never had access to list namespaces")
	}
}

func AccessAsUserWithKubectlTest(
	testKubeConfigYAML string,
	testUsername string,
	expectedNamespace string,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterUserCanViewEverythingRoleBinding(t, testUsername)

		// Use the given kubeconfig with kubectl to list namespaces as the test user
		RequireEventually(t, func(requireEventually *require.Assertions) {
			kubectlCommandOutput, err := runKubectlGetNamespaces(t, testKubeConfigYAML)
			requireEventually.NoError(err)
			requireEventually.Containsf(kubectlCommandOutput, expectedNamespace, "actual output: %q", kubectlCommandOutput)
		}, accessRetryTimeout, accessRetryInterval, "user never had access to list namespaces via kubectl")
	}
}

// AccessAsGroupTest runs a generic test in which a clientUnderTest with membership in group
// testGroup tries to auth to the kube API (i.e., list namespaces).
//
// Use this function if you want to simply validate that a user can auth to the kube API (via
// a group membership) after performing a Pinniped credential exchange.
func AccessAsGroupTest(
	ctx context.Context,
	testGroup string,
	clientUnderTest kubernetes.Interface,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterGroupCanViewEverythingRoleBinding(t, testGroup)

		// Use the client which is authenticated as the test user to list namespaces
		RequireEventually(t, func(requireEventually *require.Assertions) {
			listNamespaceResponse, err := clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			requireEventually.NoError(err)
			requireEventually.NotNil(listNamespaceResponse)
			requireEventually.NotEmpty(listNamespaceResponse.Items)
		}, accessRetryTimeout, accessRetryInterval, "user never had access to list namespaces")
	}
}

func AccessAsGroupWithKubectlTest(
	testKubeConfigYAML string,
	testGroup string,
	expectedNamespace string,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterGroupCanViewEverythingRoleBinding(t, testGroup)

		// Use the given kubeconfig with kubectl to list namespaces as the test user
		RequireEventually(t, func(requireEventually *require.Assertions) {
			kubectlCommandOutput, err := runKubectlGetNamespaces(t, testKubeConfigYAML)
			requireEventually.NoError(err)
			requireEventually.Containsf(kubectlCommandOutput, expectedNamespace, "actual output: %q", kubectlCommandOutput)
		}, accessRetryTimeout, accessRetryInterval, "user never had access to list namespaces")
	}
}

func addTestClusterUserCanViewEverythingRoleBinding(t *testing.T, testUsername string) {
	t.Helper()

	CreateTestClusterRoleBinding(t,
		rbacv1.Subject{
			Kind:     rbacv1.UserKind,
			APIGroup: rbacv1.GroupName,
			Name:     testUsername,
		},
		rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: rbacv1.GroupName,
			Name:     "view",
		},
	)
	WaitForUserToHaveAccess(t, testUsername, []string{}, &authorizationv1.ResourceAttributes{
		Verb:     "get",
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	})
}

func addTestClusterGroupCanViewEverythingRoleBinding(t *testing.T, testGroup string) {
	t.Helper()

	CreateTestClusterRoleBinding(t,
		rbacv1.Subject{
			Kind:     rbacv1.GroupKind,
			APIGroup: rbacv1.GroupName,
			Name:     testGroup,
		},
		rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: rbacv1.GroupName,
			Name:     "view",
		},
	)
	WaitForUserToHaveAccess(t, "", []string{testGroup}, &authorizationv1.ResourceAttributes{
		Verb:     "get",
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	})
}

func runKubectlGetNamespaces(t *testing.T, kubeConfigYAML string) (string, error) {
	t.Helper()

	f := writeStringToTempFile(t, "pinniped-generated-kubeconfig-*", kubeConfigYAML)

	//nolint:gosec // It's okay that we are passing f.Name() to an exec command here. It was created above.
	output, err := exec.Command(
		"kubectl", "get", "namespace", "--kubeconfig", f.Name(),
	).CombinedOutput()

	return string(output), err
}

func writeStringToTempFile(t *testing.T, filename string, kubeConfigYAML string) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", filename)
	require.NoError(t, err)
	deferMe := func() {
		err := os.Remove(f.Name())
		require.NoError(t, err)
	}
	t.Cleanup(deferMe)
	_, err = f.WriteString(kubeConfigYAML)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	return f
}
