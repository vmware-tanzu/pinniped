// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestJWKSWriterControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
		wantParent controllerlib.Key
	}{
		{
			name: "no owner reference",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{},
			},
		},
		{
			name: "owner reference without correct APIVersion",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:       "FederationDomain",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "owner reference without correct Kind",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "owner reference without controller set to true",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "FederationDomain",
							Name:       "some-name",
						},
					},
				},
			},
		},
		{
			name: "correct owner reference",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "FederationDomain",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{Namespace: "some-namespace", Name: "some-name"},
		},
		{
			name: "multiple owner references",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-jwks",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "UnrelatedKind",
						},
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "FederationDomain",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{Namespace: "some-namespace", Name: "some-name"},
		},
		{
			name: "correct owner reference but wrong type",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/some-other-type",
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "FederationDomain",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-namespace",
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().FederationDomains()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewJWKSWriterController(
				nil, // labels, not needed
				nil, // kubeClient, not needed
				nil, // pinnipedClient, not needed
				secretInformer,
				federationDomainInformer,
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.secret))
			require.Equal(t, test.wantParent, filter.Parent(test.secret))
		})
	}
}

func TestJWKSWriterControllerFilterFederationDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		federationDomain configv1alpha1.FederationDomain
		wantAdd          bool
		wantUpdate       bool
		wantDelete       bool
		wantParent       controllerlib.Key
	}{
		{
			name:             "anything goes",
			federationDomain: configv1alpha1.FederationDomain{},
			wantAdd:          true,
			wantUpdate:       true,
			wantDelete:       true,
			wantParent:       controllerlib.Key{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().FederationDomains()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewJWKSWriterController(
				nil, // labels, not needed
				nil, // kubeClient, not needed
				nil, // pinnipedClient, not needed
				secretInformer,
				federationDomainInformer,
				withInformer.WithInformer,
			)

			unrelated := configv1alpha1.FederationDomain{}
			filter := withInformer.GetFilterForInformer(federationDomainInformer)
			require.Equal(t, test.wantAdd, filter.Add(&test.federationDomain))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, &test.federationDomain))
			require.Equal(t, test.wantUpdate, filter.Update(&test.federationDomain, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(&test.federationDomain))
			require.Equal(t, test.wantParent, filter.Parent(&test.federationDomain))
		})
	}
}

func TestJWKSWriterControllerSync(t *testing.T) {
	// We shouldn't run this test in parallel since it messes with a global function (generateKey).

	const namespace = "tuna-namespace"

	goodKeyPEM, err := ioutil.ReadFile("testdata/good-ec-key.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(goodKeyPEM)
	require.NotNil(t, block, "expected block to be non-nil...is goodKeyPEM a valid PEM?")
	goodKey, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	federationDomainGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "federationdomains",
	}

	goodFederationDomain := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-federationDomain",
			Namespace: namespace,
			UID:       "good-federationDomain-uid",
		},
		Spec: configv1alpha1.FederationDomainSpec{
			Issuer: "https://some-issuer.com",
		},
	}
	goodFederationDomainWithStatus := goodFederationDomain.DeepCopy()
	goodFederationDomainWithStatus.Status.Secrets.JWKS.Name = goodFederationDomainWithStatus.Name + "-jwks"

	secretGVR := schema.GroupVersionResource{
		Group:    corev1.SchemeGroupVersion.Group,
		Version:  corev1.SchemeGroupVersion.Version,
		Resource: "secrets",
	}

	newSecret := func(activeJWKPath, jwksPath string) *corev1.Secret {
		s := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      goodFederationDomainWithStatus.Status.Secrets.JWKS.Name,
				Namespace: namespace,
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         federationDomainGVR.GroupVersion().String(),
						Kind:               "FederationDomain",
						Name:               goodFederationDomain.Name,
						UID:                goodFederationDomain.UID,
						BlockOwnerDeletion: boolPtr(true),
						Controller:         boolPtr(true),
					},
				},
			},
			Type: "secrets.pinniped.dev/federation-domain-jwks",
		}
		s.Data = make(map[string][]byte)
		if activeJWKPath != "" {
			s.Data["activeJWK"] = readJWKJSON(t, activeJWKPath)
		}
		if jwksPath != "" {
			s.Data["jwks"] = readJWKJSON(t, jwksPath)
		}
		return &s
	}

	goodSecret := newSecret("testdata/good-jwk.json", "testdata/good-jwks.json")

	secretWithWrongType := newSecret("testdata/good-jwk.json", "testdata/good-jwks.json")
	secretWithWrongType.Type = "not-the-right-type"

	tests := []struct {
		name                        string
		key                         controllerlib.Key
		secrets                     []*corev1.Secret
		configKubeClient            func(*kubernetesfake.Clientset)
		configPinnipedClient        func(*pinnipedfake.Clientset)
		federationDomains           []*configv1alpha1.FederationDomain
		generateKeyErr              error
		wantGenerateKeyCount        int
		wantSecretActions           []kubetesting.Action
		wantFederationDomainActions []kubetesting.Action
		wantError                   string
	}{
		{
			name: "new federationDomain with no secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithStatus),
			},
		},
		{
			name: "federationDomain without status with existing secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			secrets: []*corev1.Secret{
				goodSecret,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithStatus),
			},
		},
		{
			name: "existing federationDomain with no secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "existing federationDomain with existing secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				goodSecret,
			},
		},
		{
			name: "deleted federationDomain",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			// Nothing to do here since Kube will garbage collect our child secret via its OwnerReference.
		},
		{
			name: "missing jwk in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("", "testdata/good-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "missing jwks in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/good-jwk.json", ""),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "wrong type in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				secretWithWrongType,
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "invalid jwk JSON in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/not-json.txt", "testdata/good-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "invalid jwks JSON in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/good-jwk.json", "testdata/not-json.txt"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "public jwk in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/public-jwk.json", "testdata/good-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "private jwks in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/good-jwk.json", "testdata/private-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "invalid jwk key in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/invalid-key-jwk.json", "testdata/good-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "invalid jwks key in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/good-jwk.json", "testdata/invalid-key-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "missing active jwks in secret",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			secrets: []*corev1.Secret{
				newSecret("testdata/good-jwk.json", "testdata/missing-active-jwks.json"),
			},
			wantGenerateKeyCount: 1,
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
		},
		{
			name: "generate key fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomainWithStatus,
			},
			generateKeyErr: errors.New("some generate error"),
			wantError:      "cannot generate secret: cannot generate key: some generate error",
		},
		{
			name: "get secret fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("get", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantError: "cannot create or update secret: cannot get secret: some get error",
		},
		{
			name: "create secret fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("create", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantError: "cannot create or update secret: cannot create secret: some create error",
		},
		{
			name: "update secret fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			secrets: []*corev1.Secret{
				newSecret("", ""),
			},
			configKubeClient: func(client *kubernetesfake.Clientset) {
				client.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantError: "cannot create or update secret: some update error",
		},
		{
			name: "get FederationDomain fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor("get", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantError: "cannot update FederationDomain: cannot get FederationDomain: some get error",
		},
		{
			name: "update federationDomain fails",
			key:  controllerlib.Key{Namespace: goodFederationDomain.Namespace, Name: goodFederationDomain.Name},
			federationDomains: []*configv1alpha1.FederationDomain{
				goodFederationDomain,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor("update", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantError: "cannot update FederationDomain: some update error",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// We shouldn't run this test in parallel since it messes with a global function (generateKey).
			generateKeyCount := 0
			generateKey = func(_ io.Reader) (interface{}, error) {
				generateKeyCount++
				return goodKey, test.generateKeyErr
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			kubeAPIClient := kubernetesfake.NewSimpleClientset()
			kubeInformerClient := kubernetesfake.NewSimpleClientset()
			for _, secret := range test.secrets {
				require.NoError(t, kubeAPIClient.Tracker().Add(secret))
				require.NoError(t, kubeInformerClient.Tracker().Add(secret))
			}
			if test.configKubeClient != nil {
				test.configKubeClient(kubeAPIClient)
			}

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()
			for _, federationDomain := range test.federationDomains {
				require.NoError(t, pinnipedAPIClient.Tracker().Add(federationDomain))
				require.NoError(t, pinnipedInformerClient.Tracker().Add(federationDomain))
			}
			if test.configPinnipedClient != nil {
				test.configPinnipedClient(pinnipedAPIClient)
			}

			kubeInformers := kubeinformers.NewSharedInformerFactory(
				kubeInformerClient,
				0,
			)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(
				pinnipedInformerClient,
				0,
			)

			c := NewJWKSWriterController(
				map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				kubeAPIClient,
				pinnipedAPIClient,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				controllerlib.WithInformer,
			)

			// Must start informers before calling TestRunSynchronously().
			kubeInformers.Start(ctx.Done())
			pinnipedInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, c)

			err := controllerlib.TestSync(t, c, controllerlib.Context{
				Context: ctx,
				Key:     test.key,
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.NoError(t, err)

			require.Equal(t, test.wantGenerateKeyCount, generateKeyCount)

			if test.wantSecretActions != nil {
				require.Equal(t, test.wantSecretActions, kubeAPIClient.Actions())
			}
			if test.wantFederationDomainActions != nil {
				require.Equal(t, test.wantFederationDomainActions, pinnipedAPIClient.Actions())
			}
		})
	}
}

func readJWKJSON(t *testing.T, path string) []byte {
	t.Helper()

	data, err := ioutil.ReadFile(path)
	require.NoError(t, err)

	// Trim whitespace from our testdata so that we match the compact JSON encoding of
	// our implementation.
	data = bytes.ReplaceAll(data, []byte(" "), []byte{})
	data = bytes.ReplaceAll(data, []byte("\n"), []byte{})

	return data
}

func boolPtr(b bool) *bool { return &b }
