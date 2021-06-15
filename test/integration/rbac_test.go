// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	v1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"

	"go.pinniped.dev/test/library"
)

func TestServiceAccountPermissions(t *testing.T) {
	// TODO: update this test to check the permissions of all service accounts
	//  For now it just checks the permissions of the impersonation proxy SA

	env := library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// impersonate the SA since it is easier than fetching a token and lets us control the group memberships
	config := rest.CopyConfig(library.NewClientConfig(t))
	config.Impersonate = rest.ImpersonationConfig{
		UserName: serviceaccount.MakeUsername(env.ConciergeNamespace, env.ConciergeAppName+"-impersonation-proxy"),
		// avoid permissions assigned to system:serviceaccounts by explicitly impersonating system:serviceaccounts:<namespace>
		// as not all clusters will have the system:service-account-issuer-discovery binding
		// system:authenticated is required for us to create selfsubjectrulesreviews
		// TODO remove this once we stop supporting Kube clusters before v1.19
		Groups: []string{serviceaccount.MakeNamespaceGroupName(env.ConciergeNamespace), user.AllAuthenticated},
	}

	ssrrClient := library.NewKubeclient(t, config).Kubernetes.AuthorizationV1().SelfSubjectRulesReviews()

	// the impersonation proxy SA has the same permissions for all checks because it should only be authorized via cluster role bindings

	expectedResourceRules := []authorizationv1.ResourceRule{
		// system:basic-user is bound to system:authenticated by default
		{Verbs: []string{"create"}, APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}},

		// the expected impersonation permissions
		{Verbs: []string{"impersonate"}, APIGroups: []string{""}, Resources: []string{"users", "groups", "serviceaccounts"}},
		{Verbs: []string{"impersonate"}, APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"*"}},

		// we bind these to system:authenticated
		{Verbs: []string{"create", "list"}, APIGroups: []string{"login.concierge." + env.APIGroupSuffix}, Resources: []string{"tokencredentialrequests"}},
		{Verbs: []string{"create", "list"}, APIGroups: []string{"identity.concierge." + env.APIGroupSuffix}, Resources: []string{"whoamirequests"}},
	}

	if otherPinnipedGroupSuffix := getOtherPinnipedGroupSuffix(t); len(otherPinnipedGroupSuffix) > 0 {
		expectedResourceRules = append(expectedResourceRules,
			// we bind these to system:authenticated in the other instance of pinniped
			authorizationv1.ResourceRule{Verbs: []string{"create", "list"}, APIGroups: []string{"login.concierge." + otherPinnipedGroupSuffix}, Resources: []string{"tokencredentialrequests"}},
			authorizationv1.ResourceRule{Verbs: []string{"create", "list"}, APIGroups: []string{"identity.concierge." + otherPinnipedGroupSuffix}, Resources: []string{"whoamirequests"}},
		)
	}

	crbs, err := library.NewKubernetesClientset(t).RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{LabelSelector: "eks.amazonaws.com/component=pod-security-policy"})
	require.NoError(t, err)
	if len(crbs.Items) > 0 {
		expectedResourceRules = append(expectedResourceRules,
			// EKS binds these to system:authenticated
			authorizationv1.ResourceRule{Verbs: []string{"use"}, APIGroups: []string{"policy"}, Resources: []string{"podsecuritypolicies"}, ResourceNames: []string{"eks.privileged"}},
		)
	}

	expectedNonResourceRules := []authorizationv1.NonResourceRule{
		// system:public-info-viewer is bound to system:authenticated and system:unauthenticated by default
		{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz", "/livez", "/readyz", "/version", "/version/"}},

		// system:discovery is bound to system:authenticated by default
		{Verbs: []string{"get"}, NonResourceURLs: []string{"/api", "/api/*", "/apis", "/apis/*",
			"/healthz", "/livez", "/openapi", "/openapi/*", "/readyz", "/version", "/version/",
		}},
	}

	// check permissions in concierge namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, env.ConciergeNamespace, expectedResourceRules, expectedNonResourceRules)

	// check permissions in supervisor namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, env.SupervisorNamespace, expectedResourceRules, expectedNonResourceRules)

	// check permissions in kube-system namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, metav1.NamespaceSystem, expectedResourceRules, expectedNonResourceRules)

	// check permissions in kube-public namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, metav1.NamespacePublic, expectedResourceRules, expectedNonResourceRules)

	// check permissions in default namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, metav1.NamespaceDefault, expectedResourceRules, expectedNonResourceRules)

	// we fake a cluster scoped selfsubjectrulesreviews check by picking a nonsense namespace
	testPermissionsInNamespace(ctx, t, ssrrClient, "some-namespace-invalid-name||pandas-are-the-best", expectedResourceRules, expectedNonResourceRules)
}

func testPermissionsInNamespace(ctx context.Context, t *testing.T, ssrrClient v1.SelfSubjectRulesReviewInterface, namespace string,
	expectedResourceRules []authorizationv1.ResourceRule, expectedNonResourceRules []authorizationv1.NonResourceRule) {
	t.Helper()

	ssrr, err := ssrrClient.Create(ctx, &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: namespace},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	assert.ElementsMatch(t, expectedResourceRules, ssrr.Status.ResourceRules)
	assert.ElementsMatch(t, expectedNonResourceRules, ssrr.Status.NonResourceRules)
}

func getOtherPinnipedGroupSuffix(t *testing.T) string {
	t.Helper()

	env := library.IntegrationEnv(t)

	var resources []*metav1.APIResourceList

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		// we need a complete discovery listing for the check we are trying to make below
		// loop since tests like TestAPIServingCertificateAutoCreationAndRotation can break discovery
		_, r, err := library.NewKubernetesClientset(t).Discovery().ServerGroupsAndResources()
		if err != nil {
			t.Logf("retrying due to partial discovery failure: %v", err)
			return false, nil
		}

		resources = r
		return true, nil
	}, 3*time.Minute, time.Second)

	var otherPinnipedGroupSuffix string

	for _, resource := range resources {
		gv, err := schema.ParseGroupVersion(resource.GroupVersion)
		require.NoError(t, err)
		for _, apiResource := range resource.APIResources {
			if apiResource.Name == "tokencredentialrequests" && gv.Group != "login.concierge."+env.APIGroupSuffix {
				require.Empty(t, otherPinnipedGroupSuffix, "only expected at most one other instance of pinniped")
				otherPinnipedGroupSuffix = strings.TrimPrefix(gv.Group, "login.concierge.")
			}
		}
	}

	return otherPinnipedGroupSuffix
}
