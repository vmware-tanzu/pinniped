// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package groupsuffix

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
)

func ExampleReplace_loginv1alpha1() {
	s, _ := Replace(loginv1alpha1.GroupName, "tuna.fish.io")
	fmt.Println(s)
	// Output: login.concierge.tuna.fish.io
}

func ExampleReplace_string() {
	s, _ := Replace("idp.supervisor.pinniped.dev", "marlin.io")
	fmt.Println(s)
	// Output: idp.supervisor.marlin.io
}
func TestMiddlware(t *testing.T) {
	const newSuffix = "some.suffix.com"

	podWithoutOwner := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{},
		},
	}

	nonPinnipedOwner := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-name",
			UID:  "some-uid",
		},
	}
	nonPinnipedOwnerGVK := corev1.SchemeGroupVersion.WithKind("Pod")
	podWithNonPinnipedOwner := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}

	var ok bool
	pinnipedOwner := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-name",
			UID:  "some-uid",
		},
	}
	pinnipedOwnerGVK := configv1alpha1.SchemeGroupVersion.WithKind("FederationDomain")
	pinnipedOwnerWithNewGroupGVK := configv1alpha1.SchemeGroupVersion.WithKind("FederationDomain")
	pinnipedOwnerWithNewGroupGVK.Group, ok = Replace(pinnipedOwnerWithNewGroupGVK.Group, newSuffix)
	require.True(t, ok)
	podWithPinnipedOwner := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pinnipedOwner, pinnipedOwnerGVK),

				// make sure we don't update the non-pinniped owner
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}
	podWithPinnipedOwnerWithNewGroup := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pinnipedOwner, pinnipedOwnerWithNewGroupGVK),

				// make sure we don't update the non-pinniped owner
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}

	federationDomainWithPinnipedOwner := &configv1alpha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			APIVersion: configv1alpha1.SchemeGroupVersion.String(),
			Kind:       "FederationDomain",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pinnipedOwner, pinnipedOwnerGVK),

				// make sure we don't update the non-pinniped owner
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}
	federationDomainWithPinnipedOwnerWithNewGroup := &configv1alpha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			APIVersion: configv1alpha1.SchemeGroupVersion.String(),
			Kind:       "FederationDomain",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pinnipedOwner, pinnipedOwnerWithNewGroupGVK),

				// make sure we don't update the non-pinniped owner
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}
	federationDomainWithNewGroupAndPinnipedOwnerWithNewGroup := &configv1alpha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			APIVersion: replaceGV(t, configv1alpha1.SchemeGroupVersion, newSuffix),
			Kind:       "FederationDomain",
		},
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(pinnipedOwner, pinnipedOwnerWithNewGroupGVK),

				// make sure we don't update the non-pinniped owner
				*metav1.NewControllerRef(nonPinnipedOwner, nonPinnipedOwnerGVK),
			},
		},
	}

	tokenCredentialRequest := &loginv1alpha1.TokenCredentialRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: loginv1alpha1.SchemeGroupVersion.String(),
			Kind:       "TokenCredentialRequest",
		},
	}
	tokenCredentialRequestWithNewGroup := &loginv1alpha1.TokenCredentialRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: replaceGV(t, loginv1alpha1.SchemeGroupVersion, newSuffix),
			Kind:       "TokenCredentialRequest",
		},
	}

	tests := []struct {
		name                                    string
		apiGroupSuffix                          string
		rt                                      *testutil.RoundTrip
		requestObj, responseObj                 kubeclient.Object
		wantNilMiddleware                       bool
		wantMutateRequests, wantMutateResponses int
		wantRequestObj, wantResponseObj         kubeclient.Object

		skip bool
	}{
		{
			name:           "api group suffix is empty",
			apiGroupSuffix: "",
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			wantNilMiddleware: true,
		},
		{
			name:           "api group suffix is default",
			apiGroupSuffix: "pinniped.dev",
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			wantNilMiddleware: true,
		},
		{
			name:           "get resource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithoutOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "get resource without pinniped.dev with non-pinniped.dev owner ref",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithNonPinnipedOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithNonPinnipedOwner,
		},
		{
			name:           "get resource without pinniped.dev with pinniped.dev owner ref",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithPinnipedOwnerWithNewGroup,
			wantMutateResponses: 1,
			wantResponseObj:     podWithPinnipedOwner,
		},
		{
			name:           "get resource with pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbGet).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequest,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequest,
		},
		{
			name:           "create resource without pinniped.dev and without owner ref",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			requestObj:          podWithoutOwner,
			responseObj:         podWithoutOwner,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      podWithoutOwner,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "create resource without pinniped.dev and with owner ref that has no pinniped.dev owner",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			requestObj:          podWithNonPinnipedOwner,
			responseObj:         podWithNonPinnipedOwner,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      podWithNonPinnipedOwner,
			wantResponseObj:     podWithNonPinnipedOwner,
		},
		{
			name:           "create resource without pinniped.dev and with owner ref that has pinniped.dev owner",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			requestObj:          podWithPinnipedOwner,
			responseObj:         podWithPinnipedOwnerWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      podWithPinnipedOwnerWithNewGroup,
			wantResponseObj:     podWithPinnipedOwner,
		},
		{
			name:           "create subresource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")).
				WithSubresource("some-subresource"),
			responseObj:         podWithPinnipedOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithPinnipedOwner,
		},
		{
			// test that both of our middleware request mutations play nicely with each other
			name:           "create resource with pinniped.dev and with owner ref that has pinniped.dev owner",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(configv1alpha1.SchemeGroupVersion.WithResource("federationdomains")),
			requestObj:          federationDomainWithPinnipedOwner,
			responseObj:         federationDomainWithPinnipedOwnerWithNewGroup,
			wantMutateRequests:  2,
			wantMutateResponses: 1,
			wantRequestObj:      federationDomainWithNewGroupAndPinnipedOwnerWithNewGroup,
			wantResponseObj:     federationDomainWithPinnipedOwner,
		},
		{
			name:           "update resource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbUpdate).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithoutOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "update resource with pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbUpdate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequest,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequest,
		},
		{
			name:           "list resource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbList).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithoutOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "list resource with pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbList).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequest,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequest,
		},
		{
			name:           "watch resource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbWatch).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithoutOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "watch resource with pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbList).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequest,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequest,
		},
		{
			name:           "patch resource without pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbPatch).
				WithNamespace("some-namespace").
				WithResource(corev1.SchemeGroupVersion.WithResource("pods")),
			responseObj:         podWithoutOwner,
			wantMutateResponses: 1,
			wantResponseObj:     podWithoutOwner,
		},
		{
			name:           "patch resource with pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbList).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequest,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequest,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if test.skip {
				t.Skip()
			}

			m := New(test.apiGroupSuffix)
			if test.wantNilMiddleware {
				require.Nil(t, m, "wanted nil middleware")
				return
			}

			m.Handle(context.Background(), test.rt)
			require.Len(t, test.rt.MutateRequests, test.wantMutateRequests)
			require.Len(t, test.rt.MutateResponses, test.wantMutateResponses)

			if test.wantMutateRequests != 0 {
				require.NotNil(t, test.requestObj, "expected test.requestObj to be set")
				objMutated := test.requestObj.DeepCopyObject().(kubeclient.Object)
				for _, mutateRequest := range test.rt.MutateRequests {
					mutateRequest := mutateRequest
					mutateRequest(objMutated)
				}
				require.Equal(t, test.wantRequestObj, objMutated, "request obj did not match")
			}

			if test.wantMutateResponses != 0 {
				require.NotNil(t, test.responseObj, "expected test.responseObj to be set")
				objMutated := test.responseObj.DeepCopyObject().(kubeclient.Object)
				for _, mutateResponse := range test.rt.MutateResponses {
					mutateResponse := mutateResponse
					mutateResponse(objMutated)
				}
				require.Equal(t, test.wantResponseObj, objMutated, "response obj did not match")
			}
		})
	}
}

func TestReplaceError(t *testing.T) {
	_, ok := Replace("bad-suffix-that-doesnt-end-in-pinniped-dot-dev", "shouldnt-matter.com")
	require.False(t, ok)

	_, ok = Replace("bad-suffix-that-end-in.prefixed-pinniped.dev", "shouldnt-matter.com")
	require.False(t, ok)
}

func TestReplaceSuffix(t *testing.T) {
	s, ok := Replace("something.pinniped.dev.something-else.pinniped.dev", "tuna.io")
	require.Equal(t, "something.pinniped.dev.something-else.tuna.io", s)
	require.True(t, ok)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		apiGroupSuffix  string
		wantErrorPrefix string
	}{
		{
			apiGroupSuffix: "happy.suffix.com",
		},
		{
			apiGroupSuffix:  "no-dots",
			wantErrorPrefix: "1 error(s):\n- must contain '.'",
		},
		{
			apiGroupSuffix:  ".starts.with.dot",
			wantErrorPrefix: "1 error(s):\n- a lowercase RFC 1123 subdomain must consist",
		},
		{
			apiGroupSuffix:  "ends.with.dot.",
			wantErrorPrefix: "1 error(s):\n- a lowercase RFC 1123 subdomain must consist",
		},
		{
			apiGroupSuffix:  ".multiple-issues.because-this-string-is-longer-than-the-253-character-limit-of-a-dns-1123-identifier-" + chars(253),
			wantErrorPrefix: "2 error(s):\n- must be no more than 253 characters\n- a lowercase RFC 1123 subdomain must consist",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.apiGroupSuffix, func(t *testing.T) {
			err := Validate(test.apiGroupSuffix)
			if test.wantErrorPrefix != "" {
				require.Error(t, err)
				require.Truef(
					t,
					strings.HasPrefix(err.Error(), test.wantErrorPrefix),
					"%q does not start with %q", err.Error(), test.wantErrorPrefix)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func replaceGV(t *testing.T, baseGV schema.GroupVersion, apiGroupSuffix string) string {
	t.Helper()
	groupName, ok := Replace(baseGV.Group, apiGroupSuffix)
	require.True(t, ok, "expected to be able to replace %q's suffix with %q", baseGV.Group, apiGroupSuffix)
	return schema.GroupVersion{Group: groupName, Version: baseGV.Version}.String()
}

func chars(count int) string {
	return strings.Repeat("a", count)
}
