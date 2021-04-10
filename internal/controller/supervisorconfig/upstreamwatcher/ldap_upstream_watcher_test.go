// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatcher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
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

func TestLDAPUpstreamWatcherControllerSync(t *testing.T) {
	t.Parallel()

	var (
		testNamespace       = "test-namespace"
		testName            = "test-name"
		testSecretName      = "test-client-secret"
		testBindUsername    = "test-bind-username"
		testBindPassword    = "test-bind-password"
		testValidSecretData = map[string][]byte{"username": []byte(testBindUsername), "password": []byte(testBindPassword)}
	)
	tests := []struct {
		name                   string
		inputUpstreams         []runtime.Object
		inputSecrets           []runtime.Object
		wantErr                string
		wantResultingCache     []provider.UpstreamLDAPIdentityProviderI
		wantResultingUpstreams []v1alpha1.LDAPIdentityProvider
	}{
		{
			name: "no LDAPIdentityProvider upstreams clears the cache",
		},
		{
			name: "one valid upstream updates the cache to include only that upstream",
			inputUpstreams: []runtime.Object{&v1alpha1.LDAPIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNamespace, Generation: 1234},
				Spec: v1alpha1.LDAPIdentityProviderSpec{
					Host: "TODO",                                                                  // TODO
					TLS:  &v1alpha1.LDAPIdentityProviderTLSSpec{CertificateAuthorityData: "TODO"}, // TODO
					Bind: v1alpha1.LDAPIdentityProviderBindSpec{SecretName: testSecretName},
					UserSearch: v1alpha1.LDAPIdentityProviderUserSearchSpec{
						Base:   "TODO", // TODO
						Filter: "TODO", // TODO
						Attributes: v1alpha1.LDAPIdentityProviderUserSearchAttributesSpec{
							Username: "TODO", // TODO
							UniqueID: "TODO", // TODO
						},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data:       testValidSecretData,
			}},
			wantResultingCache: []provider.UpstreamLDAPIdentityProviderI{
				&upstreamldap.Provider{
					Name: testName,
					// TODO test more stuff
				},
			},
			wantResultingUpstreams: []v1alpha1.LDAPIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.LDAPIdentityProviderStatus{
					Phase: "Ready",
					// TODO Conditions
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
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetLDAPIdentityProviders([]provider.UpstreamLDAPIdentityProviderI{
				&upstreamldap.Provider{Name: "initial-entry"},
			})

			controller := NewLDAPUpstreamWatcherController(
				cache,
				func(ctx context.Context, hostAndPort string) (upstreamldap.Conn, error) {
					// TODO return a fake implementation of upstreamldap.Conn, or return an error for testing errors
					return nil, nil
				},
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
				require.Equal(t, tt.wantResultingCache[i].GetName(), actualIDP.GetName())
				// TODO more assertions
			}

			actualUpstreams, err := fakePinnipedClient.IDPV1alpha1().LDAPIdentityProviders(testNamespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			// TODO maybe use something like the normalizeUpstreams() helper to make assertions about what was updated
			_ = actualUpstreams
			// require.ElementsMatch(t, tt.wantResultingUpstreams, actualUpstreams.Items)

			// Running the sync() a second time should be idempotent, and should return the same error.
			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
