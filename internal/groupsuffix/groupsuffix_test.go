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

	authv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
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
	federationDomainWithNewGroupAndPinnipedOwner := &configv1alpha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			APIVersion: replaceGV(t, configv1alpha1.SchemeGroupVersion, newSuffix).String(),
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
	federationDomainWithNewGroupAndPinnipedOwnerWithNewGroup := &configv1alpha1.FederationDomain{
		TypeMeta: metav1.TypeMeta{
			APIVersion: replaceGV(t, configv1alpha1.SchemeGroupVersion, newSuffix).String(),
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

	tokenCredentialRequest := with(
		&loginv1alpha1.TokenCredentialRequest{},
		gvk(replaceGV(t, loginv1alpha1.SchemeGroupVersion, newSuffix).WithKind("TokenCredentialRequest")),
	)
	tokenCredentialRequestWithPinnipedAuthenticator := with(
		tokenCredentialRequest,
		authenticatorAPIGroup(authv1alpha1.SchemeGroupVersion.Group),
	)
	tokenCredentialRequestWithCustomAPIGroupAuthenticator := with(
		tokenCredentialRequest,
		authenticatorAPIGroup(replaceGV(t, authv1alpha1.SchemeGroupVersion, newSuffix).Group),
	)
	tokenCredentialRequestWithNewGroup := with(
		tokenCredentialRequest,
		gvk(replaceGV(t, loginv1alpha1.SchemeGroupVersion, newSuffix).WithKind("TokenCredentialRequest")),
	)
	tokenCredentialRequestWithNewGroupAndPinnipedAuthenticator := with(
		tokenCredentialRequestWithNewGroup,
		authenticatorAPIGroup(authv1alpha1.SchemeGroupVersion.Group),
	)
	tokenCredentialRequestWithNewGroupAndCustomAPIGroupAuthenticator := with(
		tokenCredentialRequestWithNewGroup,
		authenticatorAPIGroup(replaceGV(t, authv1alpha1.SchemeGroupVersion, newSuffix).Group),
	)

	tests := []struct {
		name                                              string
		apiGroupSuffix                                    string
		rt                                                *testutil.RoundTrip
		requestObj, responseObj                           kubeclient.Object
		wantNilMiddleware                                 bool
		wantMutateRequests, wantMutateResponses           int
		wantMutateRequestErrors, wantMutateResponseErrors []string
		wantRequestObj, wantResponseObj                   kubeclient.Object
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
			requestObj:          with(&metav1.PartialObjectMetadata{}, gvk(loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequest"))),
			responseObj:         tokenCredentialRequestWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      with(&metav1.PartialObjectMetadata{}, gvk(replaceGV(t, loginv1alpha1.SchemeGroupVersion, newSuffix).WithKind("TokenCredentialRequest"))),
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
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
			// test that multiple of our middleware request mutations play nicely with each other
			name:           "create resource with pinniped.dev and with owner ref that has pinniped.dev owner",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithNamespace("some-namespace").
				WithResource(configv1alpha1.SchemeGroupVersion.WithResource("federationdomains")),
			requestObj:          federationDomainWithPinnipedOwner,
			responseObj:         federationDomainWithNewGroupAndPinnipedOwnerWithNewGroup,
			wantMutateRequests:  2,
			wantMutateResponses: 1,
			wantRequestObj:      federationDomainWithNewGroupAndPinnipedOwnerWithNewGroup,
			wantResponseObj:     federationDomainWithNewGroupAndPinnipedOwner, // the middleware will reset object GVK for us
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
			responseObj:         tokenCredentialRequestWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
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
			responseObj:         tokenCredentialRequestWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
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
			responseObj:         tokenCredentialRequestWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
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
				WithVerb(kubeclient.VerbPatch).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequest,
			responseObj:         tokenCredentialRequestWithNewGroup,
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroup,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "create tokencredentialrequest with pinniped.dev authenticator api group",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequestWithPinnipedAuthenticator,
			responseObj:         tokenCredentialRequestWithNewGroup, // a token credential response does not contain a spec
			wantMutateRequests:  3,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroupAndCustomAPIGroupAuthenticator,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "create tokencredentialrequest with custom authenticator api group fails because api group is expected to be pinniped.dev",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:              tokenCredentialRequestWithCustomAPIGroupAuthenticator,
			responseObj:             tokenCredentialRequestWithNewGroup, // a token credential response does not contain a spec
			wantMutateRequests:      3,
			wantMutateResponses:     1,
			wantMutateRequestErrors: []string{`cannot replace token credential request "/" authenticator API group "authentication.concierge.some.suffix.com" with group suffix "some.suffix.com"`},
			wantResponseObj:         tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "create tokencredentialrequest with pinniped.dev authenticator api group and subresource",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")).
				WithSubresource("some-subresource"),
			requestObj:          tokenCredentialRequestWithPinnipedAuthenticator,
			responseObj:         tokenCredentialRequestWithNewGroup, // a token credential response does not contain a spec
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroupAndPinnipedAuthenticator,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "non-create tokencredentialrequest with pinniped.dev authenticator api group",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbList).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:          tokenCredentialRequestWithPinnipedAuthenticator,
			responseObj:         tokenCredentialRequestWithNewGroup, // a token credential response does not contain a spec
			wantMutateRequests:  1,
			wantMutateResponses: 1,
			wantRequestObj:      tokenCredentialRequestWithNewGroupAndPinnipedAuthenticator,
			wantResponseObj:     tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "create tokencredentialrequest with nil authenticator api group",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:              tokenCredentialRequest,
			responseObj:             tokenCredentialRequestWithNewGroup, // a token credential response does not contain a spec
			wantMutateRequests:      3,
			wantMutateResponses:     1,
			wantMutateRequestErrors: []string{`cannot replace token credential request "/" without authenticator API group`},
			wantResponseObj:         tokenCredentialRequestWithNewGroup, // the middleware will reset object GVK for us
		},
		{
			name:           "create tokencredentialrequest with non-*loginv1alpha1.TokenCredentialRequest",
			apiGroupSuffix: newSuffix,
			rt: (&testutil.RoundTrip{}).
				WithVerb(kubeclient.VerbCreate).
				WithResource(loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")),
			requestObj:              podWithoutOwner,
			responseObj:             podWithoutOwner,
			wantMutateRequests:      3,
			wantMutateResponses:     1,
			wantMutateRequestErrors: []string{`cannot cast obj of type *v1.Pod to *loginv1alpha1.TokenCredentialRequest`},
			wantResponseObj:         podWithoutOwner,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			m := New(test.apiGroupSuffix)
			if test.wantNilMiddleware {
				require.Nil(t, m, "wanted nil middleware")
				return
			}

			m.Handle(context.Background(), test.rt)
			require.Len(t, test.rt.MutateRequests, test.wantMutateRequests, "undesired request mutation count")
			require.Len(t, test.rt.MutateResponses, test.wantMutateResponses, "undesired response mutation count")

			if test.wantMutateRequests != 0 {
				require.NotNil(t, test.requestObj, "expected test.requestObj to be set")
				objMutated := test.requestObj.DeepCopyObject().(kubeclient.Object)
				var mutateRequestErrors []string
				for _, mutateRequest := range test.rt.MutateRequests {
					mutateRequest := mutateRequest
					if err := mutateRequest(objMutated); err != nil {
						mutateRequestErrors = append(mutateRequestErrors, err.Error())
					}
				}
				if len(test.wantMutateRequestErrors) > 0 {
					require.Equal(t, test.wantMutateRequestErrors, mutateRequestErrors, "mutate request errors did not match")
				} else {
					require.Equal(t, test.wantRequestObj, objMutated, "request obj did not match")
				}
			}

			if test.wantMutateResponses != 0 {
				require.NotNil(t, test.responseObj, "expected test.responseObj to be set")
				objMutated := test.responseObj.DeepCopyObject().(kubeclient.Object)
				var mutateResponseErrors []string
				for _, mutateResponse := range test.rt.MutateResponses {
					mutateResponse := mutateResponse
					if err := mutateResponse(objMutated); err != nil {
						mutateResponseErrors = append(mutateResponseErrors, err.Error())
					}
				}
				if len(test.wantMutateRequestErrors) > 0 {
					require.Equal(t, test.wantMutateResponseErrors, mutateResponseErrors, "mutate response errors did not match")
				} else {
					require.Equal(t, test.wantResponseObj, objMutated, "response obj did not match")
				}
			}
		})
	}
}

func TestReplaceError(t *testing.T) {
	s, ok := Replace("bad-suffix-that-doesnt-end-in-pinniped-dot-dev", "shouldnt-matter.com")
	require.Equal(t, "", s)
	require.False(t, ok)

	s, ok = Replace("bad-suffix-that-end-in.prefixed-pinniped.dev", "shouldnt-matter.com")
	require.Equal(t, "", s)
	require.False(t, ok)
}

func TestReplaceSuffix(t *testing.T) {
	s, ok := Replace("something.pinniped.dev.something-else.pinniped.dev", "tuna.io")
	require.Equal(t, "something.pinniped.dev.something-else.tuna.io", s)
	require.True(t, ok)

	// When the replace wasn't actually needed, it still returns true.
	s, ok = Unreplace("something.pinniped.dev", "pinniped.dev")
	require.Equal(t, "something.pinniped.dev", s)
	require.True(t, ok)
}

func TestUnreplaceSuffix(t *testing.T) {
	s, ok := Unreplace("something.pinniped.dev.something-else.tuna.io", "tuna.io")
	require.Equal(t, "something.pinniped.dev.something-else.pinniped.dev", s)
	require.True(t, ok)

	// When the unreplace wasn't actually needed, it still returns true.
	s, ok = Unreplace("something.pinniped.dev", "pinniped.dev")
	require.Equal(t, "something.pinniped.dev", s)
	require.True(t, ok)

	// When the unreplace was needed but did not work, return false.
	s, ok = Unreplace("something.pinniped.dev.something-else.tuna.io", "salmon.io")
	require.Equal(t, "", s)
	require.False(t, ok)
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
			wantErrorPrefix: "must contain '.'",
		},
		{
			apiGroupSuffix:  ".starts.with.dot",
			wantErrorPrefix: "a lowercase RFC 1123 subdomain must consist",
		},
		{
			apiGroupSuffix:  "ends.with.dot.",
			wantErrorPrefix: "a lowercase RFC 1123 subdomain must consist",
		},
		{
			apiGroupSuffix:  ".multiple-issues.because-this-string-is-longer-than-the-253-character-limit-of-a-dns-1123-identifier-" + chars(253),
			wantErrorPrefix: "[must be no more than 253 characters, a lowercase RFC 1123 subdomain must consist",
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

type withFunc func(obj kubeclient.Object)

func with(obj kubeclient.Object, withFuncs ...withFunc) kubeclient.Object {
	obj = obj.DeepCopyObject().(kubeclient.Object)
	for _, withFunc := range withFuncs {
		withFunc(obj)
	}
	return obj
}

func gvk(gvk schema.GroupVersionKind) withFunc {
	return func(obj kubeclient.Object) {
		obj.GetObjectKind().SetGroupVersionKind(gvk)
	}
}

func authenticatorAPIGroup(apiGroup string) withFunc {
	return func(obj kubeclient.Object) {
		tokenCredentialRequest := obj.(*loginv1alpha1.TokenCredentialRequest)
		tokenCredentialRequest.Spec.Authenticator.APIGroup = &apiGroup
	}
}

//nolint:unparam // the apiGroupSuffix parameter might always be the same, but this is nice for test readability
func replaceGV(t *testing.T, baseGV schema.GroupVersion, apiGroupSuffix string) schema.GroupVersion {
	t.Helper()
	groupName, ok := Replace(baseGV.Group, apiGroupSuffix)
	require.True(t, ok, "expected to be able to replace %q's suffix with %q", baseGV.Group, apiGroupSuffix)
	return schema.GroupVersion{Group: groupName, Version: baseGV.Version}
}

func chars(count int) string {
	return strings.Repeat("a", count)
}
