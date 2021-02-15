// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package impersonationtoken contains a test utility to generate a token to be used against our
// impersonation proxy.
//
// It is its own package to fix import cycles involving concierge/scheme, testutil, and groupsuffix.
package impersonationtoken

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/internal/groupsuffix"
)

func Make(
	t *testing.T,
	token string,
	authenticator *corev1.TypedLocalObjectReference,
	apiGroupSuffix string,
) string {
	t.Helper()

	// The impersonation test token should be a base64-encoded TokenCredentialRequest object.  The API
	// group of the TokenCredentialRequest object, and its Spec.Authenticator, should match whatever
	// is installed on the cluster. This API group is usually replaced by the kubeclient middleware,
	// but this object is not touched by the middleware since it is in a HTTP header. Therefore, we
	// need to make a manual edit here.
	loginConciergeGroupName, ok := groupsuffix.Replace(loginv1alpha1.GroupName, apiGroupSuffix)
	require.True(t, ok, "couldn't replace suffix of %q with %q", loginv1alpha1.GroupName, apiGroupSuffix)
	tokenCredentialRequest := loginv1alpha1.TokenCredentialRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenCredentialRequest",
			APIVersion: loginConciergeGroupName + "/v1alpha1",
		},
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token:         token,
			Authenticator: *authenticator.DeepCopy(),
		},
	}

	// It is assumed that the provided authenticator uses the default pinniped.dev API group, since
	// this is usually replaced by the kubeclient middleware. Since we are not going through the
	// kubeclient middleware, we need to make this replacement ourselves.
	require.NotNil(t, tokenCredentialRequest.Spec.Authenticator.APIGroup, "expected authenticator to have non-nil API group")
	authenticatorAPIGroup, ok := groupsuffix.Replace(*tokenCredentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
	require.True(t, ok, "couldn't replace suffix of %q with %q", *tokenCredentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
	tokenCredentialRequest.Spec.Authenticator.APIGroup = &authenticatorAPIGroup

	scheme := conciergescheme.New(loginConciergeGroupName, apiGroupSuffix)
	codecs := serializer.NewCodecFactory(scheme)
	respInfo, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
	require.True(t, ok, "couldn't find serializer info for media type")

	reqJSON, err := runtime.Encode(respInfo.PrettySerializer, &tokenCredentialRequest)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(reqJSON)
}
