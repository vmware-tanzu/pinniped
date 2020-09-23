// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

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

// accessAsUserTest runs a generic test in which a clientUnderTest operating with username
// testUsername tries to auth to the kube API (i.e., list namespaces).
//
// Use this function if you want to simply validate that a user can auth to the kube API after
// performing a Pinniped credential exchange.
func accessAsUserTest(
	ctx context.Context,
	adminClient kubernetes.Interface,
	testUsername string,
	clientUnderTest kubernetes.Interface,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterUserCanViewEverythingRoleBinding(ctx, t, adminClient, testUsername)

		// Use the client which is authenticated as the test user to list namespaces
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotEmpty(t, listNamespaceResponse.Items)
	}
}

func accessAsUserWithKubectlTest(
	ctx context.Context,
	adminClient kubernetes.Interface,
	testKubeConfigYAML string,
	testUsername string,
	expectedNamespace string,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterUserCanViewEverythingRoleBinding(ctx, t, adminClient, testUsername)

		// Use the given kubeconfig with kubectl to list namespaces as the test user
		var kubectlCommandOutput string
		var err error
		var canListNamespaces = func() bool {
			kubectlCommandOutput, err = runKubectlGetNamespaces(t, testKubeConfigYAML)
			return err == nil
		}

		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.Contains(t, kubectlCommandOutput, expectedNamespace)
	}
}

// accessAsGroupTest runs a generic test in which a clientUnderTest with membership in group
// testGroup tries to auth to the kube API (i.e., list namespaces).
//
// Use this function if you want to simply validate that a user can auth to the kube API (via
// a group membership) after performing a Pinniped credential exchange.
func accessAsGroupTest(
	ctx context.Context,
	adminClient kubernetes.Interface,
	testGroup string,
	clientUnderTest kubernetes.Interface,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterGroupCanViewEverythingRoleBinding(ctx, t, adminClient, testGroup)

		// Use the client which is authenticated as the test user to list namespaces
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotEmpty(t, listNamespaceResponse.Items)
	}
}

func accessAsGroupWithKubectlTest(
	ctx context.Context,
	adminClient kubernetes.Interface,
	testKubeConfigYAML string,
	testGroup string,
	expectedNamespace string,
) func(t *testing.T) {
	return func(t *testing.T) {
		addTestClusterGroupCanViewEverythingRoleBinding(ctx, t, adminClient, testGroup)

		// Use the given kubeconfig with kubectl to list namespaces as the test user
		var kubectlCommandOutput string
		var err error
		var canListNamespaces = func() bool {
			kubectlCommandOutput, err = runKubectlGetNamespaces(t, testKubeConfigYAML)
			return err == nil
		}

		assert.Eventually(t, canListNamespaces, accessRetryTimeout, accessRetryInterval)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.Contains(t, kubectlCommandOutput, expectedNamespace)
	}
}

func addTestClusterUserCanViewEverythingRoleBinding(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, testUsername string) {
	addTestClusterRoleBinding(ctx, t, adminClient, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "integration-test-user-readonly-role-binding",
		},
		Subjects: []rbacv1.Subject{{
			Kind:     rbacv1.UserKind,
			APIGroup: rbacv1.GroupName,
			Name:     testUsername,
		}},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: rbacv1.GroupName,
			Name:     "view",
		},
	})
}

func addTestClusterGroupCanViewEverythingRoleBinding(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, testGroup string) {
	addTestClusterRoleBinding(ctx, t, adminClient, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "integration-test-group-readonly-role-binding",
		},
		Subjects: []rbacv1.Subject{{
			Kind:     rbacv1.GroupKind,
			APIGroup: rbacv1.GroupName,
			Name:     testGroup,
		}},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: rbacv1.GroupName,
			Name:     "view",
		},
	})
}

func addTestClusterRoleBinding(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, binding *rbacv1.ClusterRoleBinding) {
	_, err := adminClient.RbacV1().ClusterRoleBindings().Get(ctx, binding.Name, metav1.GetOptions{})
	if err != nil {
		// "404 not found" errors are acceptable, but others would be unexpected
		statusError, isStatus := err.(*errors.StatusError)
		require.True(t, isStatus)
		require.Equal(t, http.StatusNotFound, int(statusError.Status().Code))

		_, err = adminClient.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = adminClient.RbacV1().ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Test failed to clean up after itself")
	})
}

func runKubectlGetNamespaces(t *testing.T, kubeConfigYAML string) (string, error) {
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
