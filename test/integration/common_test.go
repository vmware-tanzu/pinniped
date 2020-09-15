/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

		// Use the client which is authenticated as the test user to list namespaces
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, 3*time.Second, 250*time.Millisecond)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotEmpty(t, listNamespaceResponse.Items)
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

		// Use the client which is authenticated as the test user to list namespaces
		var listNamespaceResponse *v1.NamespaceList
		var err error
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientUnderTest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, 3*time.Second, 250*time.Millisecond)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		require.NotEmpty(t, listNamespaceResponse.Items)
	}
}
