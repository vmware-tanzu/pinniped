// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/discovery"

	"go.pinniped.dev/test/testlib"
)

func TestGetAPIResourceList(t *testing.T) { //nolint:gocyclo // each t.Run is pretty simple, but there are many
	env := testlib.IntegrationEnv(t)

	client := testlib.NewKubernetesClientset(t)
	groups, resources, err := client.Discovery().ServerGroupsAndResources()

	// discovery can have partial failures when an API service is unavailable (i.e. because of TestAPIServingCertificateAutoCreationAndRotation)
	// we ignore failures for groups that are not relevant to this test
	if err != nil {
		discoveryFailed := &discovery.ErrGroupDiscoveryFailed{}
		isDiscoveryFailed := errors.As(err, &discoveryFailed)
		require.True(t, isDiscoveryFailed, err)
		for gv, gvErr := range discoveryFailed.Groups {
			if strings.HasSuffix(gv.Group, "."+env.APIGroupSuffix) {
				require.NoError(t, gvErr)
			}
		}
	}

	makeGV := func(firstSegment, secondSegment string) schema.GroupVersion {
		return schema.GroupVersion{
			Group:   fmt.Sprintf("%s.%s.%s", firstSegment, secondSegment, env.APIGroupSuffix),
			Version: "v1alpha1",
		}
	}
	loginConciergeGV := makeGV("login", "concierge")
	identityConciergeGV := makeGV("identity", "concierge")
	authenticationConciergeGV := makeGV("authentication", "concierge")
	configConciergeGV := makeGV("config", "concierge")
	idpSupervisorGV := makeGV("idp", "supervisor")
	configSupervisorGV := makeGV("config", "supervisor")
	clientSecretSupervisorGV := makeGV("clientsecret", "supervisor")

	tests := []struct {
		group             metav1.APIGroup
		resourceByVersion map[string][]metav1.APIResource
	}{
		{
			group: metav1.APIGroup{
				Name: loginConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: loginConciergeGV.String(),
						Version:      loginConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: loginConciergeGV.String(),
					Version:      loginConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				loginConciergeGV.String(): {
					{
						Name:         "tokencredentialrequests",
						SingularName: "tokencredentialrequest",
						Kind:         "TokenCredentialRequest",
						Verbs:        []string{"create", "list"},
						Namespaced:   false,
						Categories:   []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: identityConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: identityConciergeGV.String(),
						Version:      identityConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: identityConciergeGV.String(),
					Version:      identityConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				identityConciergeGV.String(): {
					{
						Name:         "whoamirequests",
						SingularName: "whoamirequest",
						Kind:         "WhoAmIRequest",
						Verbs:        []string{"create", "list"},
						Namespaced:   false,
						Categories:   []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: clientSecretSupervisorGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: clientSecretSupervisorGV.String(),
						Version:      clientSecretSupervisorGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: clientSecretSupervisorGV.String(),
					Version:      clientSecretSupervisorGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				clientSecretSupervisorGV.String(): {
					{
						Name:         "oidcclientsecretrequests",
						SingularName: "oidcclientsecretrequest",
						Kind:         "OIDCClientSecretRequest",
						Verbs:        []string{"create", "list"},
						Namespaced:   true,
						Categories:   []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: configSupervisorGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: configSupervisorGV.String(),
						Version:      configSupervisorGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: configSupervisorGV.String(),
					Version:      configSupervisorGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				configSupervisorGV.String(): {
					{
						Name:         "federationdomains",
						SingularName: "federationdomain",
						Namespaced:   true,
						Kind:         "FederationDomain",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
					{
						Name:       "federationdomains/status",
						Namespaced: true,
						Kind:       "FederationDomain",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "oidcclients",
						SingularName: "oidcclient",
						Namespaced:   true,
						Kind:         "OIDCClient",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
					{
						Name:       "oidcclients/status",
						Namespaced: true,
						Kind:       "OIDCClient",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: idpSupervisorGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: idpSupervisorGV.String(),
						Version:      idpSupervisorGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: idpSupervisorGV.String(),
					Version:      idpSupervisorGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				idpSupervisorGV.String(): {
					{
						Name:         "oidcidentityproviders",
						SingularName: "oidcidentityprovider",
						Namespaced:   true,
						Kind:         "OIDCIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "oidcidentityproviders/status",
						Namespaced: true,
						Kind:       "OIDCIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "ldapidentityproviders",
						SingularName: "ldapidentityprovider",
						Namespaced:   true,
						Kind:         "LDAPIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "ldapidentityproviders/status",
						Namespaced: true,
						Kind:       "LDAPIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "activedirectoryidentityproviders",
						SingularName: "activedirectoryidentityprovider",
						Namespaced:   true,
						Kind:         "ActiveDirectoryIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "activedirectoryidentityproviders/status",
						Namespaced: true,
						Kind:       "ActiveDirectoryIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "githubidentityproviders",
						SingularName: "githubidentityprovider",
						Namespaced:   true,
						Kind:         "GitHubIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "githubidentityproviders/status",
						Namespaced: true,
						Kind:       "GitHubIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: configConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: configConciergeGV.String(),
						Version:      configConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: configConciergeGV.String(),
					Version:      configConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				configConciergeGV.String(): {
					{
						Name:         "credentialissuers",
						SingularName: "credentialissuer",
						Namespaced:   false,
						Kind:         "CredentialIssuer",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
					{
						Name:       "credentialissuers/status",
						Namespaced: false,
						Kind:       "CredentialIssuer",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: authenticationConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: authenticationConciergeGV.String(),
						Version:      authenticationConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: authenticationConciergeGV.String(),
					Version:      authenticationConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				authenticationConciergeGV.String(): {
					{
						Name:         "webhookauthenticators",
						SingularName: "webhookauthenticator",
						Namespaced:   false,
						Kind:         "WebhookAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
					},
					{
						Name:       "webhookauthenticators/status",
						Namespaced: false,
						Kind:       "WebhookAuthenticator",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "jwtauthenticators",
						SingularName: "jwtauthenticator",
						Namespaced:   false,
						Kind:         "JWTAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
					},
					{
						Name:       "jwtauthenticators/status",
						Namespaced: false,
						Kind:       "JWTAuthenticator",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
	}

	t.Run("every Pinniped API has explicit test coverage", func(t *testing.T) {
		t.Parallel()
		testedGroups := map[string]bool{}
		for _, tt := range tests {
			testedGroups[tt.group.Name] = true
		}
		foundPinnipedGroups := 0
		for _, g := range groups {
			if !strings.Contains(g.Name, env.APIGroupSuffix) {
				continue
			}
			foundPinnipedGroups++
			assert.Truef(t, testedGroups[g.Name], "expected group %q to have assertions defined", g.Name)
		}
		require.Equal(t, len(testedGroups), foundPinnipedGroups)
	})

	t.Run("every API categorized appropriately", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}
			for _, a := range r.APIResources {
				if strings.HasSuffix(a.Name, "/status") {
					continue
				}
				assert.Containsf(t, a.Categories, "pinniped", "expected resource %q to be in the 'pinniped' category", a.Name)
				assert.NotContainsf(t, a.Categories, "all", "expected resource %q not to be in the 'all' category", a.Name)
			}
		}
	})

	t.Run("every concierge API is cluster scoped", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}

			if !strings.Contains(r.GroupVersion, ".concierge.") {
				continue
			}

			for _, a := range r.APIResources {
				assert.False(t, a.Namespaced, "concierge APIs must be cluster scoped: %#v", a)
			}
		}
	})

	t.Run("every API has a status subresource", func(t *testing.T) {
		t.Parallel()

		aggregatedAPIs := sets.NewString("tokencredentialrequests", "whoamirequests", "oidcclientsecretrequests")

		var regular, status []string

		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}

			for _, a := range r.APIResources {
				if aggregatedAPIs.Has(a.Name) {
					continue // skip our special aggregated APIs with their own magical properties
				}

				if strings.HasSuffix(a.Name, "/status") {
					status = append(status, strings.TrimSuffix(a.Name, "/status"))
				} else {
					regular = append(regular, a.Name)
				}
			}
		}

		assert.Equal(t, regular, status)
	})

	t.Run("every API can show its docs to the user via kubectl explain, including aggregated APIs, and everything has a description", func(t *testing.T) {
		t.Parallel()

		// Log the version of kubectl to make it appear in CI output for easier debugging.
		runKubectlVersion(t)

		foundFieldNames := 0

		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}

			for _, a := range r.APIResources {
				if strings.HasSuffix(a.Name, "/status") {
					// skip status subresources for this test, as they don't work with `kubectl explain`
					continue
				}

				// Note that this test might indirectly depend on the kubectl discovery cache, found in $HOME/.kube/cache/discovery.
				// If you are working on changing API type struct comments, then you may need to clear your discovery cache
				// (or wait ~10 minutes for the cache to expire) for the new comments to appear in the `kubectl explain` results.
				foundFieldNames += requireKubectlExplainShowsDescriptionForResource(t, a.Name, a.Kind, r.GroupVersion)
			}
		}

		// manually update this value whenever you add additional fields to an API resource and then run the generator
		totalExpectedAPIFields := 310

		// Because we are parsing text from `kubectl explain` and because the format of that text can change
		// over time, make a rudimentary assertion that this test exercised the whole tree of all fields of all
		// Pinniped API resources. Without this, the test could accidentally skip parts of the tree if the
		// format has changed.
		require.Equal(t, totalExpectedAPIFields, foundFieldNames,
			"Expected to find all known fields of all Pinniped API resources. "+
				"You may will need to update this expectation if you added new fields to the API types.",
		)
	})

	t.Run("Pinniped resources do not have short names", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}
			for _, a := range r.APIResources {
				assert.Empty(t, a.ShortNames, "expected resource %q not to have any short names", a.Name)
			}
		}
	})

	for _, tt := range tests {
		t.Run(tt.group.Name, func(t *testing.T) {
			t.Parallel()
			require.Contains(t, groups, tt.group.DeepCopy())

			for groupVersion, expectedResources := range tt.resourceByVersion {
				// Find the actual resource list and make a copy.
				var actualResourceList *metav1.APIResourceList
				for _, resource := range resources {
					if resource.GroupVersion == groupVersion {
						actualResourceList = resource.DeepCopy()
					}
				}
				require.NotNilf(t, actualResourceList, "could not find groupVersion %s", groupVersion)

				for i := range actualResourceList.APIResources {
					// Because its hard to predict the storage version hash (e.g. "t/+v41y+3e4="), we just don't
					// worry about comparing that field.
					actualResourceList.APIResources[i].StorageVersionHash = ""

					// These fields were empty for a long time but started to be non-empty at some Kubernetes version.
					// The filled-in fields were first noticed when CI tested against a 1.27 pre-release.
					// To make this test pass on all versions of Kube, just ignore these fields for now.
					actualResourceList.APIResources[i].Group = ""
					actualResourceList.APIResources[i].Version = ""
					if strings.HasSuffix(actualResourceList.APIResources[i].Name, "/status") {
						actualResourceList.APIResources[i].SingularName = ""
					}
				}
				require.ElementsMatch(t, expectedResources, actualResourceList.APIResources, "unexpected API resources")
			}
		})
	}
}

// safe to run in parallel with serial tests since it only reads CRDs, see main_test.go.
func TestCRDAdditionalPrinterColumns_Parallel(t *testing.T) {
	// AdditionalPrinterColumns can be set on a CRD to make `kubectl get` return those columns in its table output.
	// The main purpose of this test is to fail when we add a new CRD without considering which
	// AdditionalPrinterColumns to set on it. This test will force us to consider it and make an explicit choice.
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	// AdditionalPrinterColumns are not returned by the Kube discovery endpoints,
	// so "discover" them in the CRD definitions instead.
	apiExtensionsV1Client := testlib.NewAPIExtensionsV1Client(t)
	crdList, err := apiExtensionsV1Client.CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	addSuffix := func(base string) string {
		return base + "." + env.APIGroupSuffix
	}

	// Since we're checking that AdditionalPrinterColumns exists on every CRD then we might as well also
	// assert which fields are set as AdditionalPrinterColumns.
	// Ideally, every CRD should show some kind of identifying info, some kind of status, and Age.
	expectedColumnsPerCRDVersion := map[string]map[string][]apiextensionsv1.CustomResourceColumnDefinition{
		addSuffix("credentialissuers.config.concierge"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "ProxyMode", Type: "string", JSONPath: ".spec.impersonationProxy.mode"},
				// CredentialIssuer status is a list of strategies, each with its own status. Unfortunately,
				// AdditionalPrinterColumns cannot show multiple results, e.g. a list of strategy types where
				// the status is equal to Successful. See https://github.com/kubernetes/kubernetes/issues/67268.
				// Although this selector can evaluate to multiple results, the Kube CRD implementation of JSONPath
				// will always only show the first result. Thus, this column will show the first successful strategy
				// type, which is the same thing that `pinniped get kubeconfig` looks for, so the value of this
				// column represents the current default strategy that will be used by `pinniped get kubeconfig`.
				{Name: "DefaultStrategy", Type: "string", JSONPath: `.status.strategies[?(@.status == "Success")].type`},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("webhookauthenticators.authentication.concierge"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Endpoint", Type: "string", JSONPath: ".spec.endpoint"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("jwtauthenticators.authentication.concierge"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Issuer", Type: "string", JSONPath: ".spec.issuer"},
				{Name: "Audience", Type: "string", JSONPath: ".spec.audience"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("activedirectoryidentityproviders.idp.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Host", Type: "string", JSONPath: ".spec.host"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("federationdomains.config.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Issuer", Type: "string", JSONPath: ".spec.issuer"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("ldapidentityproviders.idp.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Host", Type: "string", JSONPath: ".spec.host"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("oidcidentityproviders.idp.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Issuer", Type: "string", JSONPath: ".spec.issuer"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("githubidentityproviders.idp.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Host", Type: "string", JSONPath: ".spec.githubAPI.host"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
		addSuffix("oidcclients.config.supervisor"): {
			"v1alpha1": []apiextensionsv1.CustomResourceColumnDefinition{
				{Name: "Privileged Scopes", Type: "string", JSONPath: `.spec.allowedScopes[?(@ == "pinniped:request-audience")]`},
				{Name: "Client Secrets", Type: "integer", JSONPath: ".status.totalClientSecrets"},
				{Name: "Status", Type: "string", JSONPath: ".status.phase"},
				{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
			},
		},
	}

	// the current CRDs that we ship as part of Pinniped
	expectedPinnipedCRDNames := []string{
		"activedirectoryidentityproviders.idp.supervisor." + env.APIGroupSuffix,
		"credentialissuers.config.concierge." + env.APIGroupSuffix,
		"federationdomains.config.supervisor." + env.APIGroupSuffix,
		"githubidentityproviders.idp.supervisor." + env.APIGroupSuffix,
		"jwtauthenticators.authentication.concierge." + env.APIGroupSuffix,
		"ldapidentityproviders.idp.supervisor." + env.APIGroupSuffix,
		"oidcclients.config.supervisor." + env.APIGroupSuffix,
		"oidcidentityproviders.idp.supervisor." + env.APIGroupSuffix,
		"webhookauthenticators.authentication.concierge." + env.APIGroupSuffix,
	}

	actualPinnipedCRDNames := make([]string, 0)

	for _, crd := range crdList.Items {
		if !strings.Contains(crd.Spec.Group, env.APIGroupSuffix) {
			continue // skip non-Pinniped CRDs
		}

		// Found a Pinniped CRD, so let's check it for AdditionalPrinterColumns.
		actualPinnipedCRDNames = append(actualPinnipedCRDNames, crd.Name)

		for _, version := range crd.Spec.Versions {
			expectedColumns, ok := expectedColumnsPerCRDVersion[crd.Name][version.Name]
			assert.Truef(t, ok,
				"should have found an expected AdditionalPrinterColumns for CRD %q version %q: "+
					"please make sure that some useful AdditionalPrinterColumns are defined on the CRD and update this test's expectations",
				crd.Name, version.Name)
			assert.Equalf(t, expectedColumns, version.AdditionalPrinterColumns,
				"CRD %q version %q had unexpected AdditionalPrinterColumns", crd.Name, version.Name)
		}
	}

	// Make sure that the logic of this test did not accidentally skip a CRD that it should have interrogated.
	require.ElementsMatch(t, expectedPinnipedCRDNames, actualPinnipedCRDNames,
		"did not find expected number of Pinniped CRDs to check for additionalPrinterColumns")
}

func requireKubectlExplainShowsDescriptionForResource(t *testing.T, resourceName string, resourceKind string, resourceGroupVersion string) int {
	// Run kubectl explain on the resource.
	output := runKubectlExplain(t, resourceName, resourceGroupVersion)

	// Check that the output is as expected.
	if strings.Contains(output, "GROUP: ") {
		// Starting in kubectl v1.27, kubectl split the group and version into two separate fields in the output.
		splitGroupAndVersion := strings.Split(resourceGroupVersion, "/")
		require.Len(t, splitGroupAndVersion, 2)
		require.Regexp(t, `(?m)^GROUP:\s+`+regexp.QuoteMeta(splitGroupAndVersion[0])+`$`, output)
		require.Regexp(t, `(?m)^VERSION:\s+`+regexp.QuoteMeta(splitGroupAndVersion[1])+`$`, output)
	} else {
		// kubectl used to show "VERSION: clientsecret.supervisor.pinniped.dev/v1alpha1" and not have any "GROUP:"
		require.Regexp(t, `(?m)^VERSION:\s+`+regexp.QuoteMeta(resourceGroupVersion)+`$`, output)
	}
	require.Regexp(t, `(?m)^KIND:\s+`+regexp.QuoteMeta(resourceKind)+`$`, output)
	require.Regexp(t, `(?m)^DESCRIPTION:$`, output)

	// Use assert here so that the test keeps running when a description is empty, so we can find all the empty descriptions.
	assert.NotRegexp(t, `(?m)^\s*<empty>\s*$`, output, "resource or field should not have an empty description in kubectl explain")

	if resourceName == "whoamirequests.spec" {
		// This is an exception because this field is declared to be an empty struct in its type definition. It is
		// not a leaf field because it is a struct, but it also has no children because the struct contains no fields.
		// So it has neither the `FIELD:` section nor the `FIELDS:` section in the output.
		return 0
	}

	if !strings.Contains(output, "\nFIELDS:\n") {
		// We must have explained a leaf field, which has no children fields.
		return 0
	}

	// Otherwise, we must have explained a resource or field which has children fields, so it should have a fields list.
	// Grab everything after the line that says `FIELDS:`.
	fieldsSectionMatches := regexp.MustCompile(`(?s).+\nFIELDS:\n(.+)`).FindStringSubmatch(output)
	require.Len(t, fieldsSectionMatches, 2)
	allFieldsDescribedText := fieldsSectionMatches[1]

	// Grab the names of all the fields from the fields description.
	foundFieldNames := 0
	fieldNames := []string{}
	for _, line := range strings.Split(allFieldsDescribedText, "\n") {
		if strings.HasPrefix(line, "    ") {
			// Field names are indented by exactly 2 or 3 spaces (depending on the version of kubectl).
			// Skip lines that are indented deeper (by at least 4 spaces), which are field descriptions.
			// Starting in kubectl v1.27, field names became indented by 3 spaces.
			continue
		}
		if len(strings.TrimSpace(line)) == 0 {
			// Ignore empty lines.
			continue
		}
		// Field name lines start with exactly 2 or 3 spaces (depending on the version of kubectl), then the field name,
		// then some tabs/spaces, then the field type. Grab just the field name.
		// Starting in kubectl v1.27, field names became indented by 3 spaces.
		fieldsNameMatches := regexp.MustCompile(`^ {2,3}(\S+)\s+`).FindStringSubmatch(line)
		require.Len(t, fieldsNameMatches, 2, fmt.Sprintf("field name line which did not match: %s\nwhole actual value:\n%s", line, output))
		fieldName := fieldsNameMatches[1]
		fieldNames = append(fieldNames, fieldName)
		t.Logf("  Found field: %s.%s", resourceName, fieldName)
	}
	require.Greater(t, len(fieldNames), 0, "should have found some field names in the kubectl explain output, but didn't find any")
	foundFieldNames += len(fieldNames)

	// For each field, check to see that docs were provided for that field by making a recursive call to this function.
	for _, fieldName := range fieldNames {
		if fieldName == "kind" || fieldName == "metadata" || fieldName == "apiVersion" {
			// Skip these since the docs are implemented by k8s packages, so we can assume that they are correct.
			continue
		}
		foundFieldNames += requireKubectlExplainShowsDescriptionForResource(t, fmt.Sprintf("%s.%s", resourceName, fieldName), resourceKind, resourceGroupVersion)
	}

	return foundFieldNames
}

func runKubectlVersion(t *testing.T) {
	t.Helper()
	t.Log("Running: kubectl version")
	out, err := exec.Command("kubectl", "version").CombinedOutput()
	require.NoError(t, err)
	t.Log(string(out))
}

func runKubectlExplain(t *testing.T, resourceName string, apiVersion string) string {
	t.Helper()
	var stdOut, stdErr bytes.Buffer
	cmd := exec.Command("kubectl", "explain", resourceName, "--api-version", apiVersion, "--output", "plaintext-openapiv2")
	t.Log("Running:", cmd.String())
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Logf("Running kubectl explain had non-zero exit code."+
			"\nkubectl explain stdout: %s\nkubectl explain stderr: %s", stdOut.String(), stdErr.String())
	}
	require.NoError(t, err)
	return stdOut.String()
}
