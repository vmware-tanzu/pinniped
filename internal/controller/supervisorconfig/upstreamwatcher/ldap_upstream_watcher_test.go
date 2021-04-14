// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatcher

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/upstreamldap"
)

func TestLDAPUpstreamWatcherControllerFilterSecrets(t *testing.T) {
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
				Type:       corev1.SecretTypeBasicAuth,
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "a secret of the wrong type",
			secret: &corev1.Secret{
				Type:       "this-is-the-wrong-type",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
		{
			name: "resource of a data type which is not watched by this controller",
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
			ldapIDPInformer := pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders()
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			withInformer := testutil.NewObservableWithInformerOption()

			NewLDAPUpstreamWatcherController(nil, nil, nil, ldapIDPInformer, secretInformer, withInformer.WithInformer)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.secret))
		})
	}
}

func TestLDAPUpstreamWatcherControllerFilterLDAPIdentityProviders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		idp        metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "any LDAPIdentityProvider",
			idp: &v1alpha1.LDAPIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			ldapIDPInformer := pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders()
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			withInformer := testutil.NewObservableWithInformerOption()

			NewLDAPUpstreamWatcherController(nil, nil, nil, ldapIDPInformer, secretInformer, withInformer.WithInformer)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(ldapIDPInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.idp))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.idp))
			require.Equal(t, test.wantUpdate, filter.Update(test.idp, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.idp))
		})
	}
}

// Wrap the func into a struct so the test can do deep equal assertions on instances of upstreamldap.Provider.
type comparableDialer struct {
	f upstreamldap.LDAPDialerFunc
}

func (d *comparableDialer) Dial(ctx context.Context, hostAndPort string) (upstreamldap.Conn, error) {
	return d.f(ctx, hostAndPort)
}

func TestLDAPUpstreamWatcherControllerSync(t *testing.T) {
	t.Parallel()
	now := metav1.NewTime(time.Now().UTC())

	const (
		testNamespace        = "test-namespace"
		testName             = "test-name"
		testSecretName       = "test-bind-secret"
		testBindUsername     = "test-bind-username"
		testBindPassword     = "test-bind-password"
		testHost             = "ldap.example.com:123"
		testUserSearchBase   = "test-user-search-base"
		testUserSearchFilter = "test-user-search-filter"
		testUsernameAttrName = "test-username-attr"
		testUIDAttrName      = "test-uid-attr"
	)

	testValidSecretData := map[string][]byte{"username": []byte(testBindUsername), "password": []byte(testBindPassword)}

	testCA, err := certauthority.New("test CA", time.Minute)
	require.NoError(t, err)
	testCABundle := testCA.Bundle()
	testCABundleBase64Encoded := base64.StdEncoding.EncodeToString(testCABundle)

	successfulDialer := &comparableDialer{
		f: func(ctx context.Context, hostAndPort string) (upstreamldap.Conn, error) {
			// TODO return a fake implementation of upstreamldap.Conn, or return an error for testing errors
			return nil, nil
		},
	}

	validUpstream := &v1alpha1.LDAPIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNamespace, Generation: 1234},
		Spec: v1alpha1.LDAPIdentityProviderSpec{
			Host: testHost,
			TLS:  &v1alpha1.LDAPIdentityProviderTLSSpec{CertificateAuthorityData: testCABundleBase64Encoded},
			Bind: v1alpha1.LDAPIdentityProviderBindSpec{SecretName: testSecretName},
			UserSearch: v1alpha1.LDAPIdentityProviderUserSearchSpec{
				Base:   testUserSearchBase,
				Filter: testUserSearchFilter,
				Attributes: v1alpha1.LDAPIdentityProviderUserSearchAttributesSpec{
					Username: testUsernameAttrName,
					UniqueID: testUIDAttrName,
				},
			},
		},
	}
	modifiedCopyOfValidUpstream := func(editFunc func(*v1alpha1.LDAPIdentityProvider)) *v1alpha1.LDAPIdentityProvider {
		deepCopy := validUpstream.DeepCopy()
		editFunc(deepCopy)
		return deepCopy
	}

	providerForValidUpstream := &upstreamldap.Provider{
		Name:         testName,
		Host:         testHost,
		CABundle:     testCABundle,
		BindUsername: testBindUsername,
		BindPassword: testBindPassword,
		UserSearch: &upstreamldap.UserSearch{
			Base:              testUserSearchBase,
			Filter:            testUserSearchFilter,
			UsernameAttribute: testUsernameAttrName,
			UIDAttribute:      testUIDAttrName,
		},
		Dialer: successfulDialer, // the dialer passed to the controller's constructor should have been passed through
	}

	tests := []struct {
		name                   string
		inputUpstreams         []runtime.Object
		inputSecrets           []runtime.Object
		ldapDialer             upstreamldap.LDAPDialer
		wantErr                string
		wantResultingCache     []*upstreamldap.Provider
		wantResultingUpstreams []v1alpha1.LDAPIdentityProvider
	}{
		{
			name: "no LDAPIdentityProvider upstreams clears the cache",
		},
		{
			name:           "one valid upstream updates the cache to include only that upstream",
			ldapDialer:     successfulDialer,
			inputUpstreams: []runtime.Object{validUpstream},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantResultingCache: []*upstreamldap.Provider{providerForValidUpstream},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded bind secret",
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded TLS configuration",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:               "missing secret",
			ldapDialer:         successfulDialer,
			inputUpstreams:     []runtime.Object{validUpstream},
			inputSecrets:       []runtime.Object{},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretNotFound",
							Message:            fmt.Sprintf(`secret "%s" not found`, testSecretName),
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded TLS configuration",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:           "secret has wrong type",
			ldapDialer:     successfulDialer,
			inputUpstreams: []runtime.Object{validUpstream},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       "some-other-type",
				Data:       testValidSecretData,
			}},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretWrongType",
							Message:            fmt.Sprintf(`referenced Secret "%s" has wrong type "some-other-type" (should be "kubernetes.io/basic-auth")`, testSecretName),
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded TLS configuration",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:           "secret is missing key",
			ldapDialer:     successfulDialer,
			inputUpstreams: []runtime.Object{validUpstream},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
			}},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretMissingKeys",
							Message:            fmt.Sprintf(`referenced Secret "%s" is missing required keys ["username" "password"]`, testSecretName),
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded TLS configuration",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:       "CertificateAuthorityData is not base64 encoded",
			ldapDialer: successfulDialer,
			inputUpstreams: []runtime.Object{modifiedCopyOfValidUpstream(func(upstream *v1alpha1.LDAPIdentityProvider) {
				upstream.Spec.TLS.CertificateAuthorityData = "this-is-not-base64-encoded"
			})},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded bind secret",
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            "certificateAuthorityData is invalid: illegal base64 data at input byte 4",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:       "CertificateAuthorityData is not valid pem data",
			ldapDialer: successfulDialer,
			inputUpstreams: []runtime.Object{modifiedCopyOfValidUpstream(func(upstream *v1alpha1.LDAPIdentityProvider) {
				upstream.Spec.TLS.CertificateAuthorityData = base64.StdEncoding.EncodeToString([]byte("this is not pem data"))
			})},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded bind secret",
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            "certificateAuthorityData is invalid: no certificates found",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:       "nil TLS configuration",
			ldapDialer: successfulDialer,
			inputUpstreams: []runtime.Object{modifiedCopyOfValidUpstream(func(upstream *v1alpha1.LDAPIdentityProvider) {
				upstream.Spec.TLS = nil
			})},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantResultingCache: []*upstreamldap.Provider{
				{
					Name:         testName,
					Host:         testHost,
					CABundle:     nil,
					BindUsername: testBindUsername,
					BindPassword: testBindPassword,
					UserSearch: &upstreamldap.UserSearch{
						Base:              testUserSearchBase,
						Filter:            testUserSearchFilter,
						UsernameAttribute: testUsernameAttrName,
						UIDAttribute:      testUIDAttrName,
					},
					Dialer: successfulDialer, // the dialer passed to the controller's constructor should have been passed through
				},
			},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded bind secret",
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "no TLS configuration provided",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:       "non-nil TLS configuration with empty CertificateAuthorityData",
			ldapDialer: successfulDialer,
			inputUpstreams: []runtime.Object{modifiedCopyOfValidUpstream(func(upstream *v1alpha1.LDAPIdentityProvider) {
				upstream.Spec.TLS.CertificateAuthorityData = ""
			})},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantResultingCache: []*upstreamldap.Provider{
				{
					Name:         testName,
					Host:         testHost,
					CABundle:     nil,
					BindUsername: testBindUsername,
					BindPassword: testBindPassword,
					UserSearch: &upstreamldap.UserSearch{
						Base:              testUserSearchBase,
						Filter:            testUserSearchFilter,
						UsernameAttribute: testUsernameAttrName,
						UIDAttribute:      testUIDAttrName,
					},
					Dialer: successfulDialer, // the dialer passed to the controller's constructor should have been passed through
				},
			},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "BindSecretValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded bind secret",
							ObservedGeneration: 1234,
						},
						{
							Type:               "TLSConfigurationValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded TLS configuration",
							ObservedGeneration: 1234,
						},
					},
				},
			}},
		},
		{
			name:       "one valid upstream and one invalid upstream updates the cache to include only the valid upstream",
			ldapDialer: successfulDialer,
			inputUpstreams: []runtime.Object{validUpstream, modifiedCopyOfValidUpstream(func(upstream *v1alpha1.LDAPIdentityProvider) {
				upstream.Name = "other-upstream"
				upstream.Generation = 42
				upstream.Spec.Bind.SecretName = "non-existent-secret"
			})},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantErr:            controllerlib.ErrSyntheticRequeue.Error(),
			wantResultingCache: []*upstreamldap.Provider{providerForValidUpstream},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "other-upstream", Generation: 42},
					Status: v1alpha1.LDAPIdentityProviderStatus{
						Phase: "Error",
						Conditions: []v1alpha1.Condition{
							{
								Type:               "BindSecretValid",
								Status:             "False",
								LastTransitionTime: now,
								Reason:             "SecretNotFound",
								Message:            fmt.Sprintf(`secret "%s" not found`, "non-existent-secret"),
								ObservedGeneration: 42,
							},
							{
								Type:               "TLSConfigurationValid",
								Status:             "True",
								LastTransitionTime: now,
								Reason:             "Success",
								Message:            "loaded TLS configuration",
								ObservedGeneration: 42,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
					Status: v1alpha1.LDAPIdentityProviderStatus{
						Phase: "Ready",
						Conditions: []v1alpha1.Condition{
							{
								Type:               "BindSecretValid",
								Status:             "True",
								LastTransitionTime: now,
								Reason:             "Success",
								Message:            "loaded bind secret",
								ObservedGeneration: 1234,
							},
							{
								Type:               "TLSConfigurationValid",
								Status:             "True",
								LastTransitionTime: now,
								Reason:             "Success",
								Message:            "loaded TLS configuration",
								ObservedGeneration: 1234,
							},
						},
					},
				},
			},
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
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetLDAPIdentityProviders([]provider.UpstreamLDAPIdentityProviderI{
				&upstreamldap.Provider{Name: "initial-entry"},
			})

			controller := NewLDAPUpstreamWatcherController(
				cache,
				successfulDialer,
				fakePinnipedClient,
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
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

			actualIDPList := cache.GetLDAPIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := range actualIDPList {
				actualIDP := actualIDPList[i].(*upstreamldap.Provider)
				require.Equal(t, tt.wantResultingCache[i], actualIDP)
			}

			actualUpstreams, err := fakePinnipedClient.IDPV1alpha1().LDAPIdentityProviders(testNamespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			// Assert on the expected Status of the upstreams. Preprocess the upstreams a bit so that they're easier to assert against.
			normalizedActualUpstreams := normalizeLDAPUpstreams(actualUpstreams.Items, now)
			require.Equal(t, len(tt.wantResultingUpstreams), len(normalizedActualUpstreams))
			for i := range tt.wantResultingUpstreams {
				// Require each separately to get a nice diff when the test fails.
				require.Equal(t, tt.wantResultingUpstreams[i], normalizedActualUpstreams[i])
			}

			// Running the sync() a second time should be idempotent, and should return the same error.
			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func normalizeLDAPUpstreams(upstreams []v1alpha1.LDAPIdentityProvider, now metav1.Time) []v1alpha1.LDAPIdentityProvider {
	result := make([]v1alpha1.LDAPIdentityProvider, 0, len(upstreams))
	for _, u := range upstreams {
		normalized := u.DeepCopy()

		// We're only interested in comparing the status, so zero out the spec.
		normalized.Spec = v1alpha1.LDAPIdentityProviderSpec{}

		// Round down the LastTransitionTime values to `now` if they were just updated. This makes
		// it much easier to encode assertions about the expected timestamps.
		for i := range normalized.Status.Conditions {
			if time.Since(normalized.Status.Conditions[i].LastTransitionTime.Time) < 5*time.Second {
				normalized.Status.Conditions[i].LastTransitionTime = now
			}
		}
		result = append(result, *normalized)
	}

	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}
