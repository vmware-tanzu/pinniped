// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcupstreamwatcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	expiringcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	supervisorinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
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
			name: "should return true for a secret of the type secrets.pinniped.dev/oidc-client",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/oidc-client",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type Opaque",
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type TLS",
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return false for a secret of the wrong type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/not-the-oidc-client-type",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
		{
			name: "should return false for resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := supervisorfake.NewSimpleClientset()
			pinnipedInformers := supervisorinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			cache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]upstreamprovider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			withInformer := testutil.NewObservableWithInformerOption()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			New(
				cache,
				nil,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				secretInformer,
				configMapInformer,
				logger,
				withInformer.WithInformer,
				expiringcache.NewExpiring(),
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

func TestOIDCUpstreamWatcherControllerFilterConfigMaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cm         metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "any configmap",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := supervisorfake.NewSimpleClientset()
			pinnipedInformers := supervisorinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			cache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]upstreamprovider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			withInformer := testutil.NewObservableWithInformerOption()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			New(
				cache,
				nil,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				secretInformer,
				configMapInformer,
				logger,
				withInformer.WithInformer,
				expiringcache.NewExpiring(),
			)

			unrelated := corev1.ConfigMap{}
			filter := withInformer.GetFilterForInformer(configMapInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.cm))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.cm))
			require.Equal(t, test.wantUpdate, filter.Update(test.cm, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.cm))
		})
	}
}

func TestOIDCUpstreamWatcherControllerSync(t *testing.T) {
	t.Parallel()
	now := metav1.NewTime(time.Now().UTC())
	earlier := metav1.NewTime(now.Add(-1 * time.Hour).UTC())

	// Start another test server that answers discovery successfully.
	testIssuerURL, testIssuerCA := newTestIssuer(t)
	testIssuerCABase64 := base64.StdEncoding.EncodeToString([]byte(testIssuerCA))
	testIssuerAuthorizeURL, err := url.Parse("https://example.com/authorize")
	require.NoError(t, err)
	testIssuerRevocationURL, err := url.Parse("https://example.com/revoke")
	require.NoError(t, err)

	wrongCA, err := certauthority.New("foo", time.Hour)
	require.NoError(t, err)
	wrongCABase64 := base64.StdEncoding.EncodeToString(wrongCA.Bundle())

	happyAdditionalAuthorizeParametersValidCondition := metav1.Condition{
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
		testAdditionalParams         = []idpv1alpha1.Parameter{{Name: "prompt", Value: "consent"}, {Name: "foo", Value: "bar"}}
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
		inputResources         []runtime.Object
		inputValidatorCache    func(*testing.T) map[oidcDiscoveryCacheKey]*oidcDiscoveryCacheValue
		wantErr                string
		wantLogs               []string
		wantResultingCache     []*oidctestutil.TestUpstreamOIDCIdentityProvider
		wantResultingUpstreams []idpv1alpha1.OIDCIdentityProvider
	}{
		{
			name: "no upstreams",
		},
		{
			name: "missing client Secret",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{},
			wantErr:        controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"False","reason":"SecretNotFound","message":"secret \"test-client-secret\" not found"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","reason":"SecretNotFound","message":"secret \"test-client-secret\" not found","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "False", LastTransitionTime: now, Reason: "SecretNotFound",
							Message: `secret "test-client-secret" not found`},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration"},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "client Secret has wrong type",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "some-other-type",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"False","reason":"SecretWrongType","message":"referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","reason":"SecretWrongType","message":"referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "False", LastTransitionTime: now, Reason: "SecretWrongType",
							Message: `referenced Secret "test-client-secret" has wrong type "some-other-type" (should be "secrets.pinniped.dev/oidc-client")`},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration"},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "secret is missing key",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"False","reason":"SecretMissingKeys","message":"referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","reason":"SecretMissingKeys","message":"referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "False", LastTransitionTime: now, Reason: "SecretMissingKeys",
							Message: `referenced Secret "test-client-secret" is missing required keys ["clientID" "clientSecret"]`},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration"},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle is invalid base64",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: "invalid-base64",
					},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"False","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7","error":"OIDCIdentityProvider has a failing condition"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidTLSConfig",
							Message: `spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7`},
						{Type: "TLSConfigurationValid", Status: "False", LastTransitionTime: now, Reason: "InvalidTLSConfig",
							Message: "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7"},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle does not have any certificates",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("not-a-pem-ca-bundle")),
					},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: no certificates found"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"False","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: no certificates found"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: no certificates found","error":"OIDCIdentityProvider has a failing condition"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","reason":"InvalidTLSConfig","message":"spec.tls.certificateAuthorityData is invalid: no certificates found","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidTLSConfig",
							Message: `spec.tls.certificateAuthorityData is invalid: no certificates found`},
						{Type: "TLSConfigurationValid", Status: "False", LastTransitionTime: now, Reason: "InvalidTLSConfig",
							Message: "spec.tls.certificateAuthorityData is invalid: no certificates found"},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"failed to parse issuer URL: parse \"%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\": invalid URL escape \"%in\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: no TLS configuration provided"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"failed to parse issuer URL: parse \"%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\": invalid URL escape \"%in\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `failed to parse issuer URL: parse "%invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": invalid URL escape "%in"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: no TLS configuration provided"},
					},
				},
			}},
		},
		{
			name: "issuer is insecure http URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: strings.Replace(testIssuerURL, "https", "http", 1),
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have \"https\" scheme, not \"http\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: no TLS configuration provided"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have \"https\" scheme, not \"http\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `issuer URL '` + strings.Replace(testIssuerURL, "https", "http", 1) + `' must have "https" scheme, not "http"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: no TLS configuration provided"},
					},
				},
			}},
		},
		{
			name: "issuer contains a query param",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "?sub=foo",
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"issuer URL '` + testIssuerURL + `?sub=foo' cannot contain query or fragment component"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: no TLS configuration provided"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"issuer URL '` + testIssuerURL + `?sub=foo' cannot contain query or fragment component","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `issuer URL '` + testIssuerURL + "?sub=foo" + `' cannot contain query or fragment component`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: no TLS configuration provided"},
					},
				},
			}},
		},
		{
			name: "issuer contains a fragment",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "#fragment",
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"issuer URL '` + testIssuerURL + `#fragment' cannot contain query or fragment component"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: no TLS configuration provided"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"issuer URL '` + testIssuerURL + `#fragment' cannot contain query or fragment component","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `issuer URL '` + testIssuerURL + "#fragment" + `' cannot contain query or fragment component`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: no TLS configuration provided"},
					},
				},
			}},
		},
		{
			name: "really long issuer with invalid CA bundle",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: wrongCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateIssuer","message":"failed to perform OIDC discovery","namespace":"test-namespace","name":"test-name","issuer":"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","error":"Get \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": tls: failed to verify certificate: x509: certificate signed by unknown authority"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\":\nGet \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": tls: failed to verify certificate: x509: certificate signed by unknown authority"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\":\nGet \"` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration\": tls: failed to verify certificate: x509: certificate signed by unknown authority","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":` + "\n" +
								`Get "` + testIssuerURL + `/valid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns invalid authorize URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/invalid",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `failed to parse authorization endpoint URL: parse "%": invalid URL escape "%"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns invalid revocation URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/invalid-revocation-url",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"failed to parse revocation endpoint URL: parse \"%\": invalid URL escape \"%\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"failed to parse revocation endpoint URL: parse \"%\": invalid URL escape \"%\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `failed to parse revocation endpoint URL: parse "%": invalid URL escape "%"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure authorize URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"authorization endpoint URL 'http://example.com/authorize' must have \"https\" scheme, not \"http\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"authorization endpoint URL 'http://example.com/authorize' must have \"https\" scheme, not \"http\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `authorization endpoint URL 'http://example.com/authorize' must have "https" scheme, not "http"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure revocation URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure-revocation-url",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"revocation endpoint URL 'http://example.com/revoke' must have \"https\" scheme, not \"http\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"revocation endpoint URL 'http://example.com/revoke' must have \"https\" scheme, not \"http\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `revocation endpoint URL 'http://example.com/revoke' must have "https" scheme, not "http"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure token URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/insecure-token-url",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"token endpoint URL 'http://example.com/token' must have \"https\" scheme, not \"http\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"token endpoint URL 'http://example.com/token' must have \"https\" scheme, not \"http\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `token endpoint URL 'http://example.com/token' must have "https" scheme, not "http"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns no token URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/missing-token-url",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"token endpoint URL '' must have \"https\" scheme, not \"\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"token endpoint URL '' must have \"https\" scheme, not \"\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `token endpoint URL '' must have "https" scheme, not ""`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer returns no auth URL",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/missing-auth-url",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"InvalidResponse","message":"authorization endpoint URL '' must have \"https\" scheme, not \"\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"InvalidResponse","message":"authorization endpoint URL '' must have \"https\" scheme, not \"\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "InvalidResponse",
							Message: `authorization endpoint URL '' must have "https" scheme, not ""`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "upstream with error becomes valid",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name", UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes:   append(testAdditionalScopes, "xyz", "openid"), // adds openid unnecessarily
						AllowPasswordGrant: true,
					},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						{Type: "ClientCredentialsSecretValid", Status: "False", LastTransitionTime: earlier, Reason: "SomeError1",
							Message: "some previous error 1"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: earlier, Reason: "SomeError2",
							Message: "some previous error 2"},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration"},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with default authorizationConfig",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration"},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "valid upstream which already exists in the OIDC discovery validation cache, should skip performing OIDC discovery again and just use cached discovery results",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/this-path-does-not-exist",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					// Was previously validated, so already has conditions.
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			inputValidatorCache: func(t *testing.T) map[oidcDiscoveryCacheKey]*oidcDiscoveryCacheValue {
				// Create a working OIDC discovery validator cache entry for the working issuer and CA bundle.
				certPool := x509.NewCertPool()
				require.True(t, certPool.AppendCertsFromPEM([]byte(testIssuerCA)))
				httpClient := phttp.Default(certPool)
				httpClient.Timeout = time.Minute // same timeout as in the production code
				testCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				t.Cleanup(cancel)
				// Really do OIDC discovery, so we can put the real result into the cache.
				discoveredProvider, err := coreosoidc.NewProvider(coreosoidc.ClientContext(testCtx, httpClient), testIssuerURL)
				require.NoError(t, err)
				cacheValue := &oidcDiscoveryCacheValue{
					provider: discoveredProvider,
					client:   httpClient,
				}
				// Create the cache key to use with the above entry, and cache it at the issuer value that was
				// configured in the OIDCIdentityProvider. If the production code tries to perform OIDC discovery
				// on that URL, it will fail with a 404. But if the production code correctly reads the pre-cached
				// discovery result from this cache, then it should skip discovery and use the value from this cache
				// without encountering any errors.
				cacheKey := oidcDiscoveryCacheKey{
					issuer:       testIssuerURL + "/this-path-does-not-exist",
					caBundleHash: sha256.Sum256([]byte(testIssuerCA)),
				}
				// Put it into the initial cache for this test.
				return map[oidcDiscoveryCacheKey]*oidcDiscoveryCacheValue{
					cacheKey: cacheValue,
				}
			},
			wantLogs: []string{},
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					// Conditions are unchanged.
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "valid upstream with CA bundle read from a Secret",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
							Kind: "Secret",
							Name: "ca-bundle-secret",
							Key:  "ca.crt",
						},
					},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
			}},
			inputResources: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
					Type:       "secrets.pinniped.dev/oidc-client",
					Data:       testValidSecretData,
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ca-bundle-secret"},
					Type:       corev1.SecretTypeOpaque,
					Data:       map[string][]byte{"ca.crt": []byte(testIssuerCA)},
				},
			},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "valid upstream with CA bundle read from a ConfigMap",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
							Kind: "ConfigMap",
							Name: "ca-bundle-configmap",
							Key:  "ca.crt",
						},
					},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
			}},
			inputResources: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
					Type:       "secrets.pinniped.dev/oidc-client",
					Data:       testValidSecretData,
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ca-bundle-configmap"},
					Data:       map[string]string{"ca.crt": testIssuerCA},
				},
			},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with no revocation endpoint in the discovery document",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/valid-without-revocation",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration"},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with additionalScopes set to override the default",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					Claims: idpv1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes: testAdditionalScopes,
					},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration"},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with trailing slash and more optional settings",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/ends-with-slash/",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalScopes:              testAdditionalScopes,
						AdditionalAuthorizeParameters: testAdditionalParams,
						AllowPasswordGrant:            true,
					},
					Claims: idpv1alpha1.OIDCClaims{
						Groups:   testGroupsClaim,
						Username: testUsernameClaim,
						AdditionalClaimMappings: map[string]string{
							"downstream": "upstream",
						},
					},
				},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidConditionEarlier,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration"},
					},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
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
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "additionalAuthorizeParameters parameter names are allowed", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "has disallowed additionalAuthorizeParams keys",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
						AdditionalAuthorizeParameters: []idpv1alpha1.Parameter{
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
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"True","reason":"Success","message":"discovered issuer configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"False","reason":"DisallowedParameterName","message":"the following additionalAuthorizeParameters are not allowed: response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","reason":"DisallowedParameterName","message":"the following additionalAuthorizeParameters are not allowed: response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						{Type: "AdditionalAuthorizeParametersValid", Status: "False", LastTransitionTime: now, Reason: "DisallowedParameterName",
							Message: "the following additionalAuthorizeParameters are not allowed: " +
								"response_type,scope,client_id,state,nonce,code_challenge,code_challenge_method,redirect_uri,hd", ObservedGeneration: 1234},
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "discovered issuer configuration", ObservedGeneration: 1234},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, missing trailing slash when the OIDC discovery endpoint returns the URL with a trailing slash",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/ends-with-slash", // this does not end with slash when it should, thus this is an error case
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateIssuer","message":"failed to perform OIDC discovery","namespace":"test-namespace","name":"test-name","issuer":"` + testIssuerURL + `/ends-with-slash","error":"oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/ends-with-slash":` + "\n" + `oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/ends-with-slash" got "` + testIssuerURL + `/ends-with-slash/"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, extra trailing slash",
			inputUpstreams: []runtime.Object{&idpv1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL + "/",
					TLS:    &idpv1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client: idpv1alpha1.OIDCClient{SecretName: testSecretName},
				},
			}},
			inputResources: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateIssuer","message":"failed to perform OIDC discovery","namespace":"test-namespace","name":"test-name","issuer":"` + testIssuerURL + `/","error":"oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"ClientCredentialsSecretValid","status":"True","reason":"Success","message":"loaded client credentials"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","status":"False","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\""}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"TLSConfigurationValid","status":"True","reason":"Success","message":"spec.tls is valid: loaded TLS configuration"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"test-namespace","name":"test-name","type":"AdditionalAuthorizeParametersValid","status":"True","reason":"Success","message":"additionalAuthorizeParameters parameter names are allowed"}`,
				`{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"oidc-upstream-observer","caller":"oidcupstreamwatcher/oidc_upstream_watcher.go:<line>$oidcupstreamwatcher.(*oidcWatcherController).validateUpstream","message":"found failing condition","namespace":"test-namespace","name":"test-name","type":"OIDCDiscoverySucceeded","reason":"Unreachable","message":"failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"","error":"OIDCIdentityProvider has a failing condition"}`,
			},
			wantResultingCache: []*oidctestutil.TestUpstreamOIDCIdentityProvider{},
			wantResultingUpstreams: []idpv1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: idpv1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAdditionalAuthorizeParametersValidCondition,
						{Type: "ClientCredentialsSecretValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: now, Reason: "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/":` + "\n" +
								`oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/" got "` + testIssuerURL + `"`},
						{Type: "TLSConfigurationValid", Status: "True", LastTransitionTime: now, Reason: "Success",
							Message: "spec.tls is valid: loaded TLS configuration"},
					},
				},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakePinnipedClient := supervisorfake.NewSimpleClientset(tt.inputUpstreams...)
			pinnipedInformers := supervisorinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset(tt.inputResources...)
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			cache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]upstreamprovider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			validatorCache := expiringcache.NewExpiring()
			if tt.inputValidatorCache != nil {
				oidcValidatorCache := &ttlProviderCache{cache: validatorCache}
				// add to the underlying validatorCache using oidcValidatorCache which wraps it
				for key, value := range tt.inputValidatorCache(t) {
					oidcValidatorCache.putProvider(key, value)
				}
			}

			controller := New(
				cache,
				fakePinnipedClient,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				kubeInformers.Core().V1().ConfigMaps(),
				logger,
				controllerlib.WithInformer,
				validatorCache,
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
			if len(tt.wantLogs) > 0 {
				require.Equal(t, strings.Join(tt.wantLogs, "\n")+"\n", log.String())
			}

			actualIDPList := cache.GetOIDCIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := range actualIDPList {
				actualIDP := actualIDPList[i].(*upstreamoidc.ProviderConfig)
				require.Equal(t, tt.wantResultingCache[i].GetResourceName(), actualIDP.GetResourceName())
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

func normalizeOIDCUpstreams(upstreams []idpv1alpha1.OIDCIdentityProvider, now metav1.Time) []idpv1alpha1.OIDCIdentityProvider {
	result := make([]idpv1alpha1.OIDCIdentityProvider, 0, len(upstreams))
	for _, u := range upstreams {
		normalized := u.DeepCopy()

		// We're only interested in comparing the status, so zero out the spec.
		normalized.Spec = idpv1alpha1.OIDCIdentityProviderSpec{}

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
	server, serverCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(mux.ServeHTTP), nil)

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
			Issuer:        server.URL,
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/valid-without-revocation", serve an issuer with a valid discovery response which does not have a revocation endpoint.
	mux.HandleFunc("/valid-without-revocation/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/valid-without-revocation",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "", // none
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/invalid", serve an issuer that returns an invalid authorization URL (not parseable).
	mux.HandleFunc("/invalid/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   server.URL + "/invalid",
			AuthURL:  "%",
			TokenURL: "https://example.com/token",
		})
	})

	// At "/invalid-revocation-url", serve an issuer that returns an invalid revocation URL (not parseable).
	mux.HandleFunc("/invalid-revocation-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/invalid-revocation-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "%",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/insecure", serve an issuer that returns an insecure authorization URL (not https://).
	mux.HandleFunc("/insecure/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   server.URL + "/insecure",
			AuthURL:  "http://example.com/authorize",
			TokenURL: "https://example.com/token",
		})
	})

	// At "/insecure-revocation-url", serve an issuer that returns an insecure revocation URL (not https://).
	mux.HandleFunc("/insecure-revocation-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/insecure-revocation-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "http://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// At "/insecure-token-url", serve an issuer that returns an insecure token URL (not https://).
	mux.HandleFunc("/insecure-token-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/insecure-token-url",
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
			Issuer:        server.URL + "/missing-token-url",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
		})
	})

	// At "/missing-auth-url", serve an issuer that returns no auth URL, which is required by the spec.
	mux.HandleFunc("/missing-auth-url/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/missing-auth-url",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// handle the four issuer with trailing slash configs

	// valid case in= out=
	// handled above at the root of server.URL

	// valid case in=/ out=/
	mux.HandleFunc("/ends-with-slash/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:        server.URL + "/ends-with-slash/",
			AuthURL:       "https://example.com/authorize",
			RevocationURL: "https://example.com/revoke",
			TokenURL:      "https://example.com/token",
		})
	})

	// invalid case in= out=/
	// can be tested using /ends-with-slash/ endpoint

	// invalid case in=/ out=
	// can be tested using root endpoint

	return server.URL, string(serverCA)
}
