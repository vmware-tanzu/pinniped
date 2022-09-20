// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcupstreamwatcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testlogger"
	"go.pinniped.dev/internal/upstreamoidc"
)

func TestOIDCUpstreamWatcherControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "a secret of the right type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/oidc-client",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "a secret of the wrong type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/not-the-oidc-client-type",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
		{
			name: "resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})
			secretInformer := kubeInformers.Core().V1().Secrets()
			withInformer := testutil.NewObservableWithInformerOption()

			New(
				cache,
				nil,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				secretInformer,
				plog.Logr(), //nolint:staticcheck  // old test with no log assertions
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.secret))
		})
	}
}

func TestOIDCUpstreamWatcherControllerSync(t *testing.T) {
	t.Parallel()
	now := metav1.NewTime(time.Now().UTC())
	earlier := metav1.NewTime(now.Add(-1 * time.Hour).UTC())

	// Start another test server that answers discovery successfully.
	testIssuerCA, testIssuerURL := newTestIssuer(t)
	testIssuerCABase64 := base64.StdEncoding.EncodeToString([]byte(testIssuerCA))
	testIssuerAuthorizeURL, err := url.Parse("https://example.com/authorize")
	require.NoError(t, err)
	testIssuerRevocationURL, err := url.Parse("https://example.com/revoke")
	require.NoError(t, err)

	wrongCA, err := certauthority.New("foo", time.Hour)
	require.NoError(t, err)
	wrongCABase64 := base64.StdEncoding.EncodeToString(wrongCA.Bundle())

	happyAdditionalAuthorizeParametersValidCondition := v1alpha1.Condition{
		Type:               "AdditionalAuthorizeParametersValid",
		Status:             "True",
		Reason:             "Success",
		Message:            "additionalAuthorizeParameters parameter names are allowed",
		LastTransitionTime: now,
	}
	happyAdditionalAuthorizeParametersValidConditionEarlier := happyAdditionalAuthorizeParametersValidCondition
	happyAdditionalAuthorizeParametersValidConditionEarlier.LastTransitionTime = earlier

	var (
		testNamespace                = "test-namespace"
		testName                     = "test-name"
		testSecretName               = "test-client-secret"
		testAdditionalScopes         = []string{"scope1", "scope2", "scope3"}
		testExpectedScopes           = []string{"openid", "scope1", "scope2", "scope3"}
		testDefaultExpectedScopes    = []string{"openid", "offline_access", "email", "profile"}
		testAdditionalParams         = []v1alpha1.Parameter{{Name: "prompt", Value: "consent"}, {Name: "foo", Value: "bar"}}
		testExpectedAdditionalParams = map[string]string{"prompt": "consent", "foo": "bar"}
		testClientID                 = "test-oidc-client-id"
		testClientSecret             = "test-oidc-client-secret"
		testValidSecretData          = map[string][]byte{"clientID": []byte(testClientID), "clientSecret": []byte(testClientSecret)}
		testGroupsClaim              = "test-groups-claim"
		testUsernameClaim            = "test-username-claim"
		testUID                      = types.UID("test-uid")
	)
	tests := []struct {
		name                   string
		inputUpstreams         []runtime.Object
		inputSecrets           []runtime.Object
		wantErr                string
		wantLogs               []string
		wantResultingCache     []*oidctestutil.TestUpstreamOIDCIdentityProvider
		wantResultingUpstreams []v1alpha1.OIDCIdentityProvider
	}{
		{
			name: "no upstreams",
		},
		{
			name: "missing secret",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{},
			wantErr:      controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="secret \"test-client-secret\" not found" "reason"="SecretNotFound" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="secret \"test-client-secret\" not found" "name"="test-name" "namespace"="test-namespace" "reason"="SecretNotFound" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretNotFound",
							Message:            `secret "test-client-secret" not found`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "secret has wrong type",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "some-other-type",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")" "reason"="SecretWrongType" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")" "name"="test-name" "namespace"="test-namespace" "reason"="SecretWrongType" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretWrongType",
							Message:            `referenced Secret "test-client-secret" has wrong type "some-other-type" (should be "secrets.pinniped.dev/oidc-client")`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "secret is missing key",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]" "reason"="SecretMissingKeys" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]" "name"="test-name" "namespace"="test-namespace" "reason"="SecretMissingKeys" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretMissingKeys",
							Message:            `referenced Secret "test-client-secret" is missing required keys ["clientID" "clientSecret"]`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle is invalid base64",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: "invalid-base64",
					},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7" "reason"="InvalidTLSConfig" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidTLSConfig" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            `spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7`,
						},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle does not have any certificates",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("not-a-pem-ca-bundle")),
					},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="spec.certificateAuthorityData is invalid: no certificates found" "reason"="InvalidTLSConfig" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="spec.certificateAuthorityData is invalid: no certificates found" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidTLSConfig" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            `spec.certificateAuthorityData is invalid: no certificates found`,
						},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: "%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to parse issuer URL: parse \"%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\": invalid URL escape \"%in\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to parse issuer URL: parse \"%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\": invalid URL escape \"%in\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message:            `failed to parse issuer URL: parse "%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": invalid URL escape "%in"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer is insecure http URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: strings.Replace(testIssuerURL, "https", "http", 1),
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have \"https\" scheme, not \"http\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have \"https\" scheme, not \"http\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message:            `issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have "https" scheme, not "http"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer contains a query param",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "?sub=foo",
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="issuer URL '` + testIssuerURL + "?sub=foo" + `' cannot contain query or fragment component" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="issuer URL '` + testIssuerURL + "?sub=foo" + `' cannot contain query or fragment component" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message:            `issuer URL '` + testIssuerURL + "?sub=foo" + `' cannot contain query or fragment component`,
						},
					},
				},
			}},
		},
		{
			name: "issuer contains a fragment",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "#fragment",
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="issuer URL '` + testIssuerURL + "#fragment" + `' cannot contain query or fragment component" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="issuer URL '` + testIssuerURL + "#fragment" + `' cannot contain query or fragment component" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message:            `issuer URL '` + testIssuerURL + "#fragment" + `' cannot contain query or fragment component`,
						},
					},
				},
			}},
		},
		{
			name: "really long issuer with invalid CA bundle",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: wrongCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="Get \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": x509: certificate signed by unknown authority" "issuer"="` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\":\nGet \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": x509: certificate signed by unknown authority" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\":\nGet \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": x509: certificate signed by unknown authority" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":
Get "` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration": x509: certificate signed by unknown authority`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns invalid authorize URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/invalid",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `failed to parse authorization endpoint URL: parse "%": invalid URL escape "%"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns invalid revocation URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/invalid-revocation-url",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to parse revocation endpoint URL: parse \"%\": invalid URL escape \"%\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to parse revocation endpoint URL: parse \"%\": invalid URL escape \"%\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `failed to parse revocation endpoint URL: parse "%": invalid URL escape "%"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure authorize URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="authorization endpoint URL 'http://example.com/authorize' must have \"https\" scheme, not \"http\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="authorization endpoint URL 'http://example.com/authorize' must have \"https\" scheme, not \"http\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `authorization endpoint URL 'http://example.com/authorize' must have "https" scheme, not "http"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure revocation URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure-revocation-url",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="revocation endpoint URL 'http://example.com/revoke' must have \"https\" scheme, not \"http\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="revocation endpoint URL 'http://example.com/revoke' must have \"https\" scheme, not \"http\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `revocation endpoint URL 'http://example.com/revoke' must have "https" scheme, not "http"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure token URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure-token-url",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="token endpoint URL 'http://example.com/token' must have \"https\" scheme, not \"http\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="token endpoint URL 'http://example.com/token' must have \"https\" scheme, not \"http\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `token endpoint URL 'http://example.com/token' must have "https" scheme, not "http"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns no token URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/missing-token-url",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="token endpoint URL '' must have \"https\" scheme, not \"\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="token endpoint URL '' must have \"https\" scheme, not \"\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `token endpoint URL '' must have "https" scheme, not ""`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns no auth URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/missing-auth-url",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="authorization endpoint URL '' must have \"https\" scheme, not \"\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="authorization endpoint URL '' must have \"https\" scheme, not \"\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `authorization endpoint URL '' must have "https" scheme, not ""`,
						},
					},
				},
			}},
		},
		{
			name: "upstream with error becomes valid",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name", UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes:   append(testAdditionalScopes, "xyz", "openid"), // adds openid unnecessarily
						AllowPasswordGrant: true,
					},
					Claims: v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "False", LastTransitionTime: earlier, Reason: "SomeError1", Message: "some previous error 1"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: earlier, Reason: "SomeError2", Message: "some previous error 2"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{
				{
					Name:                     testName,
					ClientID:                 testClientID,
					AuthorizationURL:         *testIssuerAuthorizeURL,
					RevocationURL:            testIssuerRevocationURL,
					Scopes:                   append(testExpectedScopes, "xyz"), // includes openid only once
					UsernameClaim:            testUsernameClaim,
					GroupsClaim:              testGroupsClaim,
					AllowPasswordGrant:       true,
					AdditionalAuthcodeParams: map[string]string{},
					AdditionalClaimMappings:  nil, // Does not default to empty map
					ResourceUID:              testUID,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with default authorizationConfig",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{
				{
					Name:                     testName,
					ClientID:                 testClientID,
					AuthorizationURL:         *testIssuerAuthorizeURL,
					RevocationURL:            testIssuerRevocationURL,
					Scopes:                   testDefaultExpectedScopes,
					UsernameClaim:            testUsernameClaim,
					GroupsClaim:              testGroupsClaim,
					AllowPasswordGrant:       false,
					AdditionalAuthcodeParams: map[string]string{},
					AdditionalClaimMappings:  nil, // Does not default to empty map
					ResourceUID:              testUID,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with no revocation endpoint in the discovery document",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/valid-without-revocation",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{
				{
					Name:                     testName,
					ClientID:                 testClientID,
					AuthorizationURL:         *testIssuerAuthorizeURL,
					RevocationURL:            nil, // no revocation URL is set in the cached provider because none was returned by discovery
					Scopes:                   testDefaultExpectedScopes,
					UsernameClaim:            testUsernameClaim,
					GroupsClaim:              testGroupsClaim,
					AllowPasswordGrant:       false,
					AdditionalAuthcodeParams: map[string]string{},
					AdditionalClaimMappings:  nil, // Does not default to empty map
					ResourceUID:              testUID,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with additionalScopes set to override the default",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes: testAdditionalScopes,
					},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{
				{
					Name:                     testName,
					ClientID:                 testClientID,
					AuthorizationURL:         *testIssuerAuthorizeURL,
					RevocationURL:            testIssuerRevocationURL,
					Scopes:                   testExpectedScopes,
					UsernameClaim:            testUsernameClaim,
					GroupsClaim:              testGroupsClaim,
					AllowPasswordGrant:       false,
					AdditionalAuthcodeParams: map[string]string{},
					AdditionalClaimMappings:  nil, // Does not default to empty map
					ResourceUID:              testUID,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with trailing slash and more optional settings",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/ends-with-slash/",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes:              testAdditionalScopes,
						AdditionalAuthorizeParameters: testAdditionalParams,
						AllowPasswordGrant:            true,
					},
					Claims: v1alpha1.OIDCClaims{
						Groups:   testGroupsClaim,
						Username: testUsernameClaim,
						AdditionalClaimMappings: map[string]string{
							"downstream": "upstream",
						},
					},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{
				{
					Name:                     testName,
					ClientID:                 testClientID,
					AuthorizationURL:         *testIssuerAuthorizeURL,
					RevocationURL:            testIssuerRevocationURL,
					Scopes:                   testExpectedScopes, // does not include the default scopes
					UsernameClaim:            testUsernameClaim,
					GroupsClaim:              testGroupsClaim,
					AllowPasswordGrant:       true,
					AdditionalAuthcodeParams: testExpectedAdditionalParams,
					AdditionalClaimMappings: map[string]string{
						"downstream": "upstream",
					},
					ResourceUID: testUID,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "has disallowed additionalAuthorizeParams keys",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
						AdditionalAuthorizeParameters: []v1alpha1.Parameter{
							{Name: "response_type", Value: "foo"},
							{Name: "scope", Value: "foo"},
							{Name: "client_id", Value: "foo"},
							{Name: "state", Value: "foo"},
							{Name: "nonce", Value: "foo"},
							{Name: "code_challenge", Value: "foo"},
							{Name: "code_challenge_method", Value: "foo"},
							{Name: "redirect_uri", Value: "foo"},
							{Name: "hd", Value: "foo"},
							{Name: "this_one_is_allowed", Value: "foo"},
						},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="the following additionalAuthorizeParameters are not allowed: response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd" "reason"="DisallowedParameterName" "status"="False" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="the following additionalAuthorizeParameters are not allowed: response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd" "name"="test-name" "namespace"="test-namespace" "reason"="DisallowedParameterName" "type"="AdditionalAuthorizeParametersValid"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "False", LastTransitionTime: now, Reason: "DisallowedParameterName",
							Message: "the following additionalAuthorizeParameters are not allowed: " +
								"response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd", ObservedGeneration: 1234},
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, missing trailing slash when the OIDC discovery endpoint returns the URL with a trailing slash",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/ends-with-slash", // this does not end with slash when it should, thus this is an error case
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "issuer"="` + testIssuerURL + `/ends-with-slash" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/ends-with-slash":
oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/ends-with-slash" got "` + testIssuerURL + `/ends-with-slash/"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, extra trailing slash",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/",
					TLS:    &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: v1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "issuer"="` + testIssuerURL + `/" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="additionalAuthorizeParameters parameter names are allowed" "reason"="Success" "status"="True" "type"="AdditionalAuthorizeParametersValid"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/":
oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/" got "` + testIssuerURL + `"`,
						},
					},
				},
			}},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakePinnipedClient := pinnipedfake.NewSimpleClientset(tt.inputUpstreams...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset(tt.inputSecrets...)
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			testLog := testlogger.NewLegacy(t) //nolint:staticcheck  // old test with lots of log statements
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})

			controller := New(
				cache,
				fakePinnipedClient,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				testLog.Logger,
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, strings.Join(tt.wantLogs, "\n"), strings.Join(testLog.Lines(), "\n"))

			actualIDPList := cache.GetOIDCIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := range actualIDPList {
				actualIDP := actualIDPList[i].(*upstreamoidc.ProviderConfig)
				require.Equal(t, tt.wantResultingCache[i].GetName(), actualIDP.GetName())
				require.Equal(t, tt.wantResultingCache[i].GetClientID(), actualIDP.GetClientID())
				require.Equal(t, tt.wantResultingCache[i].GetAuthorizationURL().String(), actualIDP.GetAuthorizationURL().String())
				require.Equal(t, tt.wantResultingCache[i].GetUsernameClaim(), actualIDP.GetUsernameClaim())
				require.Equal(t, tt.wantResultingCache[i].GetGroupsClaim(), actualIDP.GetGroupsClaim())
				require.Equal(t, tt.wantResultingCache[i].AllowsPasswordGrant(), actualIDP.AllowsPasswordGrant())
				require.Equal(t, tt.wantResultingCache[i].GetAdditionalAuthcodeParams(), actualIDP.GetAdditionalAuthcodeParams())
				require.Equal(t, tt.wantResultingCache[i].GetAdditionalClaimMappings(), actualIDP.GetAdditionalClaimMappings())
				require.Equal(t, tt.wantResultingCache[i].GetResourceUID(), actualIDP.GetResourceUID())
				require.Equal(t, tt.wantResultingCache[i].GetRevocationURL(), actualIDP.GetRevocationURL())
				require.ElementsMatch(t, tt.wantResultingCache[i].GetScopes(), actualIDP.GetScopes())

				// We always want to use the proxy from env on these clients, so although the following assertions
				// are a little hacky, this is a cheap way to test that we are using it.
				actualTransport := unwrapTransport(t, actualIDP.Client.Transport)
				httpProxyFromEnvFunction := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
				actualTransportProxyFunction := reflect.ValueOf(actualTransport.Proxy).Pointer()
				require.Equal(t, httpProxyFromEnvFunction, actualTransportProxyFunction,
					"Transport should have used http.ProxyFromEnvironment as its Proxy func")
				// We also want a reasonable timeout on each request/response cycle for OIDC discovery and JWKS.
				require.Equal(t, time.Minute, actualIDP.Client.Timeout)
			}

			actualUpstreams, err := fakePinnipedClient.IDPV1alpha1().OIDCIdentityProviders(testNamespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			// Assert on the expected Status of the upstreams. Preprocess the upstreams a bit so that they're easier to assert against.
			require.ElementsMatch(t, tt.wantResultingUpstreams, normalizeOIDCUpstreams(actualUpstreams.Items, now))

			// Running the sync() a second time should be idempotent except for logs, and should return the same error.
			// This also helps exercise code paths where the OIDC provider discovery hits cache.
			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func unwrapTransport(t *testing.T, rt http.RoundTripper) *http.Transport {
	t.Helper()

	switch baseRT := rt.(type) {
	case *http.Transport:
		return baseRT

	case net.RoundTripperWrapper:
		return unwrapTransport(t, baseRT.WrappedRoundTripper())

	default:
		t.Fatalf("expected cached provider to have client with Transport of type *http.Transport, got: %T", baseRT)
		return nil // unreachable
	}
}

func normalizeOIDCUpstreams(upstreams []v1alpha1.OIDCIdentityProvider, now metav1.Time) []v1alpha1.OIDCIdentityProvider {
	result := make([]v1alpha1.OIDCIdentityProvider, 0, len(upstreams))
	for _, u := range upstreams {
		normalized := u.DeepCopy()

		// We're only interested in comparing the status, so zero out the spec.
		normalized.Spec = v1alpha1.OIDCIdentityProviderSpec{}

		// Round down the LastTransitionTime values to `now` if they were just updated. This makes
		// it much easier to encode assertions about the expected timestamps.
		for i := range normalized.Status.Conditions {
			if time.Since(normalized.Status.Conditions[i].LastTransitionTime.Time) < 5*time.Second {
				normalized.Status.Conditions[i].LastTransitionTime = now
			}
		}
		result = append(result, *normalized)
	}

	return result
}

func newTestIssuer(t *testing.T) (string, string) {
	mux := http.NewServeMux()
	caBundlePEM, testURL := testutil.TLSTestServer(t, mux.ServeHTTP)

	type providerJSON struct {
		Issuer        string `json:"issuer"`
		AuthURL       string `json:"authorization_endpoint"`
		TokenURL      string `json:"token_endpoint"`
		RevocationURL string `json:"revocation_endpoint,omitempty"`
		JWKSURL       string `json:"jwks_uri"`
	}

	// At the root of the server, serve an issuer with a valid discovery response.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL,
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/valid-without-revocation", serve an issuer with a valid discovery response which does not have a revocation endpoint.
	mux.HandleFunc("/valid-without-revocation/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/valid-without-revocation",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "", // none
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/invalid", serve an issuer that returns an invalid authorization URL (not parseable).
	mux.HandleFunc("/invalid/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   testURL + "/invalid",
			AuthURL:  "%",
			TokenURL: "https://example.com/token",
		})
	})

	// At "/invalid-revocation-url", serve an issuer that returns an invalid revocation URL (not parseable).
	mux.HandleFunc("/invalid-revocation-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/invalid-revocation-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "%",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/insecure", serve an issuer that returns an insecure authorization URL (not https://).
	mux.HandleFunc("/insecure/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   testURL + "/insecure",
			AuthURL:  "http://example.com/authorize",
			TokenURL: "https://example.com/token",
		})
	})

	// At "/insecure-revocation-url", serve an issuer that returns an insecure revocation URL (not https://).
	mux.HandleFunc("/insecure-revocation-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/insecure-revocation-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "http://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/insecure-token-url", serve an issuer that returns an insecure token URL (not https://).
	mux.HandleFunc("/insecure-token-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/insecure-token-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "http://example.com/token",
		})
	})

	// At "/missing-token-url", serve an issuer that returns no token URL (is required by the spec unless it's an idp which only supports
	// implicit flow, which we don't support). So for our purposes we need to always get a token url
	mux.HandleFunc("/missing-token-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/missing-token-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
		})
	})

	// At "/missing-auth-url", serve an issuer that returns no auth URL, which is required by the spec.
	mux.HandleFunc("/missing-auth-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/missing-auth-url",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// handle the four issuer with trailing slash configs

	// valid case in= out=
	// handled above at the root of testURL

	// valid case in=/ out=/
	mux.HandleFunc("/ends-with-slash/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        testURL + "/ends-with-slash/",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// invalid case in= out=/
	// can be tested using /ends-with-slash/ endpoint

	// invalid case in=/ out=
	// can be tested using root endpoint

	return caBundlePEM, testURL
}
