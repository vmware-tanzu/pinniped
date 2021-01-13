// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	accessRetryInterval = 250 * time.Millisecond
	accessRetryTimeout  = 10 * time.Second
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
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotNil(t, listNamespaceResponse)
		require.NotEmpty(t, listNamespaceResponse.Items)
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
		var kubectlCommandOutput string
		var err error
		var canListNamespaces = func() bool {
			kubectlCommandOutput, err = runKubectlGetNamespaces(t, testKubeConfigYAML)
			return err == nil
		}

		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.Containsf(t, kubectlCommandOutput, expectedNamespace, "actual output: %q", kubectlCommandOutput)
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
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotNil(t, listNamespaceResponse)
		require.NotEmpty(t, listNamespaceResponse.Items)
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
		var kubectlCommandOutput string
		var err error
		var canListNamespaces = func() bool {
			kubectlCommandOutput, err = runKubectlGetNamespaces(t, testKubeConfigYAML)
			return err == nil
		}

		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.Containsf(t, kubectlCommandOutput, expectedNamespace, "actual output: %q", kubectlCommandOutput)
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
}

func runKubectlGetNamespaces(t *testing.T, kubeConfigYAML string) (string, error) {
	t.Helper()

	f := writeStringToTempFile(t, "pinniped-generated-kubeconfig-*", kubeConfigYAML)

	//nolint: gosec // It's okay that we are passing f.Name() to an exec command here. It was created above.
	output, err := exec.Command(
		"kubectl", "get", "namespace", "--kubeconfig", f.Name(),
	).CombinedOutput()

	return string(output), err
}

func writeStringToTempFile(t *testing.T, filename string, kubeConfigYAML string) *os.File {
	t.Helper()
	f, err := ioutil.TempFile("", filename)
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
