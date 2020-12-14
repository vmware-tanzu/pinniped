// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
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

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/mocks/mocksecrethelper"
	"go.pinniped.dev/internal/testutil"
)

func TestOIDCProviderControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     corev1.Secret
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
		wantParent controllerlib.Key
	}{
		{
			name: "no owner reference",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{},
			},
		},
		{
			name: "owner reference without correct APIVersion",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:       "OIDCProvider",
							Name:       "some-name",
							Controller: boolPtr(true),
						},
					},
				},
			},
		},
		{
			name: "owner reference without correct Kind",
			secret: corev1.Secret{
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
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
							Name:       "some-name",
						},
					},
				},
			},
		},
		{
			name: "correct owner reference",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
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
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "UnrelatedKind",
						},
						{
							APIVersion: configv1alpha1.SchemeGroupVersion.String(),
							Kind:       "OIDCProvider",
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
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			secretHelper := mocksecrethelper.NewMockSecretHelper(ctrl)
			secretHelper.EXPECT().Name().Times(1).Return("some-name")

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			opcInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCProviders()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCProviderSecretsController(
				secretHelper,
				nil, // kubeClient, not needed
				secretInformer,
				opcInformer,
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(&test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, &test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(&test.secret))
			require.Equal(t, test.wantParent, filter.Parent(&test.secret))
		})
	}
}

func TestNewOIDCProviderSecretsControllerFilterOPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opc        configv1alpha1.OIDCProvider
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
		wantParent controllerlib.Key
	}{
		{
			name:       "anything goes",
			opc:        configv1alpha1.OIDCProvider{},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
			wantParent: controllerlib.Key{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			secretHelper := mocksecrethelper.NewMockSecretHelper(ctrl)
			secretHelper.EXPECT().Name().Times(1).Return("some-name")

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			opcInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCProviders()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCProviderSecretsController(
				secretHelper,
				nil, // kubeClient, not needed
				secretInformer,
				opcInformer,
				withInformer.WithInformer,
			)

			unrelated := configv1alpha1.OIDCProvider{}
			filter := withInformer.GetFilterForInformer(opcInformer)
			require.Equal(t, test.wantAdd, filter.Add(&test.opc))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, &test.opc))
			require.Equal(t, test.wantUpdate, filter.Update(&test.opc, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(&test.opc))
			require.Equal(t, test.wantParent, filter.Parent(&test.opc))
		})
	}
}

func TestOIDCProviderSecretsControllerSync(t *testing.T) {
	t.Parallel()

	const (
		namespace = "some-namespace"

		opName = "op-name"
		opUID  = "op-uid"

		secretName = "secret-name"
		secretUID  = "secret-uid"
	)

	opGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "oidcproviders",
	}

	secretGVR := schema.GroupVersionResource{
		Group:    corev1.SchemeGroupVersion.Group,
		Version:  corev1.SchemeGroupVersion.Version,
		Resource: "secrets",
	}

	goodOP := &configv1alpha1.OIDCProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opName,
			Namespace: namespace,
			UID:       opUID,
		},
	}

	goodSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			UID:       secretUID,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         opGVR.GroupVersion().String(),
					Kind:               "OIDCProvider",
					Name:               opName,
					UID:                opUID,
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

	invalidSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			UID:       secretUID,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         opGVR.GroupVersion().String(),
					Kind:               "OIDCProvider",
					Name:               opName,
					UID:                opUID,
					BlockOwnerDeletion: boolPtr(true),
					Controller:         boolPtr(true),
				},
			},
		},
	}

	once := sync.Once{}

	tests := []struct {
		name              string
		storage           func(**configv1alpha1.OIDCProvider, **corev1.Secret)
		client            func(*kubernetesfake.Clientset)
		secretHelper      func(*mocksecrethelper.MockSecretHelper)
		wantSecretActions []kubetesting.Action
		wantOPActions     []kubetesting.Action
		wantError         string
	}{
		{
			name: "OIDCProvider exists and secret does not exist",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*op = nil
				*s = nil
			},
		},
		{
			name: "OIDCProvider exists and secret exists",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*op = nil
			},
		},
		{
			name: "OIDCProvider exists and secret does not exist",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().Notify(goodOP, goodSecret).Times(1)
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewCreateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "OIDCProvider exists and valid secret exists",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, goodSecret).Times(1).Return(true)
				secretHelper.EXPECT().Notify(goodOP, goodSecret).Times(1)
			},
		},
		{
			name: "OIDCProvider exists and invalid secret exists",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, invalidSecret).Times(2).Return(false)
				secretHelper.EXPECT().Notify(goodOP, goodSecret).Times(1)
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
			},
		},
		{
			name: "OIDCProvider exists and generating a secret fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(nil, errors.New("some generate error"))
			},
			wantError: "failed to generate secret: some generate error",
		},
		{
			name: "OIDCProvider exists and invalid secret exists and upon update we learn of a valid secret",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.UID = "other-secret-uid"

				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(otherSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, goodSecret).Times(1).Return(false)
				secretHelper.EXPECT().IsValid(goodOP, goodSecret).Times(1).Return(true)
				secretHelper.EXPECT().Notify(goodOP, goodSecret).Times(1)
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
			},
		},
		{
			name: "OIDCProvider exists and invalid secret exists and get fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, goodSecret).Times(1).Return(false)
			},
			client: func(c *kubernetesfake.Clientset) {
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
			name: "OIDCProvider exists and secret does not exist and create fails",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*s = nil
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
			},
			client: func(c *kubernetesfake.Clientset) {
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
			name: "OIDCProvider exists and invalid secret exists and update fails",
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, goodSecret).Times(2).Return(false)
			},
			client: func(c *kubernetesfake.Clientset) {
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
			name: "OIDCProvider exists and invalid secret exists and update fails due to conflict",
			storage: func(op **configv1alpha1.OIDCProvider, s **corev1.Secret) {
				*s = invalidSecret.DeepCopy()
			},
			secretHelper: func(secretHelper *mocksecrethelper.MockSecretHelper) {
				secretHelper.EXPECT().Generate(goodOP).Times(1).Return(goodSecret, nil)
				secretHelper.EXPECT().IsValid(goodOP, invalidSecret).Times(3).Return(false)
				secretHelper.EXPECT().Notify(goodOP, goodSecret).Times(1)
			},
			client: func(c *kubernetesfake.Clientset) {
				c.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					var err error
					once.Do(func() { err = k8serrors.NewConflict(secretGVR.GroupResource(), namespace, errors.New("some error")) })
					return true, nil, err
				})
			},
			wantSecretActions: []kubetesting.Action{
				kubetesting.NewGetAction(secretGVR, namespace, goodSecret.Name),
				kubetesting.NewUpdateAction(secretGVR, namespace, goodSecret),
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

			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()

			kubeAPIClient := kubernetesfake.NewSimpleClientset()
			kubeInformerClient := kubernetesfake.NewSimpleClientset()

			op := goodOP.DeepCopy()
			secret := goodSecret.DeepCopy()
			if test.storage != nil {
				test.storage(&op, &secret)
			}
			if op != nil {
				require.NoError(t, pinnipedInformerClient.Tracker().Add(op))
			}
			if secret != nil {
				require.NoError(t, kubeAPIClient.Tracker().Add(secret))
				require.NoError(t, kubeInformerClient.Tracker().Add(secret))
			}

			if test.client != nil {
				test.client(kubeAPIClient)
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
			secretHelper.EXPECT().Name().Times(1).Return("some-name")
			if test.secretHelper != nil {
				test.secretHelper(secretHelper)
			}

			c := NewOIDCProviderSecretsController(
				secretHelper,
				kubeAPIClient,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
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
					Name:      opName,
				},
			})
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.NoError(t, err)

			if test.wantSecretActions == nil {
				test.wantSecretActions = []kubetesting.Action{}
			}
			require.Equal(t, test.wantSecretActions, kubeAPIClient.Actions())
		})
	}
}

func boolPtr(b bool) *bool { return &b }
