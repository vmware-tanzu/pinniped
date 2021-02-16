// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	"go.pinniped.dev/internal/mocks/mocksecrethelper"
	"go.pinniped.dev/internal/testutil"
)

func TestFederationDomainControllerFilterSecret(t *testing.T) {
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
				Type:       "secrets.pinniped.dev/federation-domain-token-signing-key",
				ObjectMeta: metav1.ObjectMeta{},
			},
		},
		{
			name: "owner reference without correct APIVersion",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/federation-domain-token-signing-key",
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
				Type: "secrets.pinniped.dev/federation-domain-token-signing-key",
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
				Type: "secrets.pinniped.dev/federation-domain-token-signing-key",
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
				Type: "secrets.pinniped.dev/federation-domain-token-signing-key",
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
				Type: "secrets.pinniped.dev/federation-domain-token-signing-key",
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
			name: "correct owner reference but wrong secret type",
			secret: &corev1.Secret{
				Type: "secrets.pinniped.dev/this-is-the-wrong-type",
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

			secretHelper := NewSymmetricSecretHelper(
				"some-name",
				map[string]string{},
				rand.Reader,
				SecretUsageTokenSigningKey,
				func(cacheKey string, cacheValue []byte) {},
			)

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().FederationDomains()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewFederationDomainSecretsController(
				secretHelper,
				nil, // secretRefFunc, not needed
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

func TestNewFederationDomainSecretsControllerFilterFederationDomain(t *testing.T) {
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

			secretHelper := NewSymmetricSecretHelper(
				"some-name",
				map[string]string{},
				rand.Reader,
				SecretUsageTokenSigningKey,
				func(cacheKey string, cacheValue []byte) {},
			)

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().FederationDomains()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewFederationDomainSecretsController(
				secretHelper,
				nil, // secretRefFunc, not needed
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

func TestFederationDomainSecretsControllerSync(t *testing.T) {
	t.Parallel()

	const (
		namespace = "some-namespace"

		federationDomainName = "federationDomain-name"
		federationDomainUID  = "federationDomain-uid"

		secretName = "secret-name"
		secretUID  = "secret-uid"
	)

	federationDomainGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "federationdomains",
	}

	secretGVR := schema.GroupVersionResource{
		Group:    corev1.SchemeGroupVersion.Group,
		Version:  corev1.SchemeGroupVersion.Version,
		Resource: "secrets",
	}

	goodFederationDomain := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      federationDomainName,
			Namespace: namespace,
			UID:       federationDomainUID,
		},
	}

	goodSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			UID:       secretUID,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         federationDomainGVR.GroupVersion().String(),
					Kind:               "FederationDomain",
					Name:               federationDomainName,
					UID:                federationDomainUID,
					BlockOwnerDeletion: boolPtr(true),
					Controller:         boolPtr(true),
				},
			},
			Labels: map[string]string{
				"some-key-0": "some-value-0",
				"some-key-1": "some-value-1",
			},
		},
		Type: "some-secret-type",
		Data: map[string][]byte{
			"some-key": []byte("some-value"),
		},
	}

	goodFederationDomainWithTokenSigningKey := goodFederationDomain.DeepCopy()
	goodFederationDomainWithTokenSigningKey.Status.Secrets.TokenSigningKey.Name = goodSecret.Name

	goodFederationDomainWithJWKS := goodFederationDomain.DeepCopy()
	goodFederationDomainWithJWKS.Status.Secrets.JWKS.Name = "some-jwks-key"

	goodFederationDomainWithJWKSAndTokenSigningKey := goodFederationDomainWithJWKS.DeepCopy()
	goodFederationDomainWithJWKSAndTokenSigningKey.Status.Secrets.TokenSigningKey = goodFederationDomainWithTokenSigningKey.Status.Secrets.TokenSigningKey

	invalidSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			UID:       secretUID,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         federationDomainGVR.GroupVersion().String(),
					Kind:               "FederationDomain",
					Name:               federationDomainName,
					UID:                federationDomainUID,
					BlockOwnerDeletion: boolPtr(true),
					Controller:         boolPtr(true),
				},
			},
		},
	}

	tests := []struct {
		name                        string
		storage                     func(**configv1alpha1.FederationDomain, **corev1.Secret)
		client                      func(*pinnipedfake.Clientset, *kubernetesfake.Clientset)
		secretHelper                func(*mocksecrethelper.MockSecretHelper)
		wantFederationDomainActions []kubetesting.Action
		wantSecretActions           []kubetesting.Action
		wantError                   string
	}{
		{
			name: "FederationDomain does not exist and secret does not exist",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*federationDomain = nil
				*s = nil
			},
		},
		{
			name: "FederationDomain does not exist and secret exists",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*federationDomain = nil
			},
		},
		{
			name: "FederationDomain exists and secret does not exist",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "FederationDomain exists and secret does not exist and upon updating FederationDomain we learn a new status field has been set",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			client: func(c *pinnipedfake.Clientset, _ *kubernetesfake.Clientset) {
				c.PrependReactor("get", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, goodFederationDomainWithJWKS, nil
				})
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithJWKSAndTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "FederationDomain exists and secret does not exist and upon updating FederationDomain we learn all status fields have been set",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			client: func(c *pinnipedfake.Clientset, _ *kubernetesfake.Clientset) {
				c.PrependReactor("get", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, goodFederationDomainWithJWKSAndTokenSigningKey, nil
				})
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "FederationDomain exists and invalid secret exists",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, invalidSecret).Times(2).Return(false)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "FederationDomain exists and generating a secret fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(nil, errors.New("some generate error"))
			},
			wantError: "failed to generate secret: some generate error",
		},
		{
			name: "FederationDomain exists and invalid secret exists and upon update we learn of a valid secret",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.UID = "other-secret-uid"

				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(otherSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, goodSecret).Times(1).Return(false)
				secretHelper.EXPECT().IsValid(goodFederationDomain, goodSecret).Times(1).Return(true)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
			},
		},
		{
			name: "FederationDomain exists and invalid secret exists and getting secret fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, goodSecret).Times(1).Return(false)
			},
			client: func(_ *pinnipedfake.Clientset, c *kubernetesfake.Clientset) {
				c.PrependReactor("get", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
			},
			wantError: fmt.Sprintf("failed to create or update secret: failed to get secret %s/%s: some get error", namespace, goodSecret.Name),
		},
		{
			name: "FederationDomain exists and secret does not exist and creating secret fails",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
			},
			client: func(_ *pinnipedfake.Clientset, c *kubernetesfake.Clientset) {
				c.PrependReactor("create", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some create error")
				})
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
			wantError: fmt.Sprintf("failed to create or update secret: failed to create secret %s/%s: some create error", namespace, goodSecret.Name),
		},
		{
			name: "FederationDomain exists and invalid secret exists and updating secret fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, goodSecret).Times(2).Return(false)
			},
			client: func(_ *pinnipedfake.Clientset, c *kubernetesfake.Clientset) {
				c.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some update error")
				})
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantError: "failed to create or update secret: some update error",
		},
		{
			name: "FederationDomain exists and invalid secret exists and updating secret fails due to conflict",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, invalidSecret).Times(3).Return(false)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			client: func(_ *pinnipedfake.Clientset, c *kubernetesfake.Clientset) {
				once := sync.Once{}
				c.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					var err error
					once.Do(func() { err = k8serrors.NewConflict(secretGVR.GroupResource(), namespace, errors.New("some error")) })
					return true, nil, err
				})
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "FederationDomain exists and invalid secret exists and getting FederationDomain fails",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, invalidSecret).Times(2).Return(false)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			client: func(c *pinnipedfake.Clientset, _ *kubernetesfake.Clientset) {
				c.PrependReactor("get", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("some get error")
				})
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
			wantError: fmt.Sprintf("failed to update federationdomain: failed to get federationdomain %s/%s: some get error", goodFederationDomainWithTokenSigningKey.Namespace, goodFederationDomainWithTokenSigningKey.Name),
		},
		{
			name: "FederationDomain exists and invalid secret exists and updating FederationDomain fails due to conflict",
			storage: func(federationDomain **configv1alpha1.FederationDomain, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodFederationDomain).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodFederationDomain, invalidSecret).Times(2).Return(false)
				secretHelper.EXPECT().ObserveActiveSecretAndUpdateParentFederationDomain(goodFederationDomain, goodSecret).Times(1).Return(goodFederationDomainWithTokenSigningKey)
			},
			client: func(c *pinnipedfake.Clientset, _ *kubernetesfake.Clientset) {
				once := sync.Once{}
				c.PrependReactor("update", "federationdomains", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					var err error
					once.Do(func() { err = k8serrors.NewConflict(secretGVR.GroupResource(), namespace, errors.New("some error")) })
					return true, nil, err
				})
			},
			wantFederationDomainActions: []kubetesting.Action{
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
				kubetesting.NewGetAction(federationDomainGVR, namespace, goodFederationDomain.Name),
				kubetesting.NewUpdateSubresourceAction(federationDomainGVR, "status", namespace, goodFederationDomainWithTokenSigningKey),
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()

			kubeAPIClient := kubernetesfake.NewSimpleClientset()
			kubeInformerClient := kubernetesfake.NewSimpleClientset()

			federationDomain := goodFederationDomain.DeepCopy()
			secret := goodSecret.DeepCopy()
			if test.storage != nil {
				test.storage(&federationDomain, &secret)
			}
			if federationDomain != nil {
				require.NoError(t, pinnipedAPIClient.Tracker().Add(federationDomain))
				require.NoError(t, pinnipedInformerClient.Tracker().Add(federationDomain))
			}
			if secret != nil {
				require.NoError(t, kubeAPIClient.Tracker().Add(secret))
				require.NoError(t, kubeInformerClient.Tracker().Add(secret))
			}

			if test.client != nil {
				test.client(pinnipedAPIClient, kubeAPIClient)
			}

			kubeInformers := kubeinformers.NewSharedInformerFactory(
				kubeInformerClient,
				0,
			)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(
				pinnipedInformerClient,
				0,
			)

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			secretHelper := mocksecrethelper.NewMockSecretHelper(ctrl)
			secretHelper.EXPECT().NamePrefix().Times(1).Return("some-name")
			if test.secretHelper != nil {
				test.secretHelper(secretHelper)
			}
			secretHelper.EXPECT().Handles(gomock.Any()).AnyTimes().Return(true)

			c := NewFederationDomainSecretsController(
				secretHelper,
				func(fd *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
					return &fd.Secrets.TokenSigningKey
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
				Key: controllerlib.Key{
					Namespace: namespace,
					Name:      federationDomainName,
				},
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.NoError(t, err)

			if test.wantFederationDomainActions == nil {
				test.wantFederationDomainActions = []kubetesting.Action{}
			}
			require.Equal(t, test.wantFederationDomainActions, pinnipedAPIClient.Actions())
			if test.wantSecretActions == nil {
				test.wantSecretActions = []kubetesting.Action{}
			}
			require.Equal(t, test.wantSecretActions, kubeAPIClient.Actions())
		})
	}
}

func boolPtr(b bool) *bool { return &b }
