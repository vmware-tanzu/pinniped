// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controller/conditionsutil"
)

func TestValidateTLSConfig(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	bundle := testCA.Bundle()
	base64EncodedBundle := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		name              string
		tlsSpec           *TLSSpec
		namespace         string
		k8sObjects        []runtime.Object
		expectedCondition *metav1.Condition
	}{
		{
			name:    "nil TLSSpec should generate a noTLSConfigurationMessage condition",
			tlsSpec: nil,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: " + noTLSConfigurationMessage,
			},
		},
		{
			name:    "empty inline ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec: &TLSSpec{},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: " + noTLSConfigurationMessage,
			},
		},
		{
			name: "valid base64 encode ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec: &TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: " + loadedTLSConfigurationMessage,
			},
		},
		{
			name: "valid base64 encoded non cert data should generate a invalidTLSCondition condition",
			tlsSpec: &TLSSpec{
				CertificateAuthorityData: "dGhpcyBpcyBzb21lIHRlc3QgZGF0YSB0aGF0IGlzIGJhc2U2NCBlbmNvZGVkIHRoYXQgaXMgbm90IGEgY2VydAo=",
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityData is invalid: " + ErrNoCertificates.Error(),
			},
		},
		{
			name: "non-base64 encoded string as ca data should generate an invalidTLSCondition condition",
			tlsSpec: &TLSSpec{
				CertificateAuthorityData: "non base64 encoded string",
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityData is invalid: illegal base64 data at input byte 3",
			},
		},
		{
			name: "supplying certificateAuthorityDataSource and certificateAuthorityData should generate an invalid condition",
			tlsSpec: &TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "super-secret",
					Key:  "ca-base64EncodedBundle",
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls is invalid: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided",
			},
		},
		{
			name: "should return ca bundle from kubernetes secret of type tls",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret-tls",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret-tls",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca-bundle": bundle,
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: loaded TLS configuration",
			},
		},
		{
			name: "should return ca bundle from kubernetes secret of type opaque",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret-opaque",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret-opaque",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca-bundle": bundle,
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: loaded TLS configuration",
			},
		},

		{
			name: "should return invalid condition when a secrets not of type tls or opaque are used as ca data source",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret-ba",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret-ba",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeBasicAuth,
					Data: map[string][]byte{
						"ca-bundle": bundle,
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityDataSource is invalid: secret awesome-namespace/awesome-secret-ba of type kubernetes.io/basic-auth cannot be used as a certificate authority data source",
			},
		},

		{
			name: "should return ca bundle from kubernetes configMap",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "ConfigMap",
					Name: "awesome-cm",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-cm",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": string(bundle),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "tls is valid: loaded TLS configuration",
			},
		},
		{
			name: "should return invalid condition when failing to read ca bundle from kubernetes secret that does not exist",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "does-not-exist",
					Key:  "does-not-matter",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-cm",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": string(bundle),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityDataSource is invalid: failed to get secret awesome-namespace/does-not-exist: secret \"does-not-exist\" not found",
			},
		},
		{
			name: "should return invalid condition when failing to read ca bundle from kubernetes configMap that does not exist",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "ConfigMap",
					Name: "does-not-exist",
					Key:  "does-not-matter",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-cm",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": string(bundle),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityDataSource is invalid: failed to get configmap awesome-namespace/does-not-exist: configmap \"does-not-exist\" not found",
			},
		},
		{
			name: "should return invalid condition when using an invalid certificate authority data source",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "SomethingElse",
					Name: "does-not-exist",
					Key:  "does-not-matter",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-cm",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": string(bundle),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "tls.certificateAuthorityDataSource is invalid: unsupported CA bundle source kind: SomethingElse",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var secretsInformer corev1informers.SecretInformer
			var configMapInformer corev1informers.ConfigMapInformer

			if len(tt.k8sObjects) > 0 {
				fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
				sharedInformers := informers.NewSharedInformerFactory(fakeClient, 0)
				configMapInformer = sharedInformers.Core().V1().ConfigMaps()
				secretsInformer = sharedInformers.Core().V1().Secrets()

				// calling the .Informer function registers this informer in the sharedinformer.
				// doing this will ensure that this informer will be sync'd when Start is called next.
				configMapInformer.Informer()
				secretsInformer.Informer()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				sharedInformers.Start(ctx.Done())
				sharedInformers.WaitForCacheSync(ctx.Done())
			}
			actualCondition, _, _, _ := ValidateTLSConfig(tt.tlsSpec, "tls", tt.namespace, secretsInformer, configMapInformer)
			require.Equal(t, tt.expectedCondition, actualCondition)
		})
	}
}

func TestReadCABundleFromK8sSecret(t *testing.T) {
	tests := []struct {
		name            string
		secretNamespace string
		secretName      string
		secretKey       string
		k8sObjects      []runtime.Object
		expectedData    string
		expectError     bool
	}{
		{
			name:            "should return error reading a non-existent secret",
			secretNamespace: "awesome-namespace",
			secretName:      "does-not-exist",
			secretKey:       "does-not-matter",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Data: map[string][]byte{
						"awesome": []byte("pinniped-is-awesome"),
					},
				},
			},
			expectedData: "",
			expectError:  true,
		},
		{
			name:            "should return error reading a non-existing key in an existing secret",
			secretNamespace: "awesome-namespace",
			secretName:      "awesome-secret",
			secretKey:       "something-else",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Data: map[string][]byte{
						"awesome": []byte("pinniped-is-awesome"),
					},
				},
			},
			expectedData: "",
			expectError:  true,
		},
		{
			name:            "should return data from existing tls secret and existing key",
			secretNamespace: "awesome-namespace",
			secretName:      "awesome-secret",
			secretKey:       "awesome",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"awesome": []byte("pinniped-is-awesome"),
					},
				},
			},
			expectedData: "pinniped-is-awesome",
			expectError:  false,
		},
		{
			name:            "should return data from existing opaque secret and existing key",
			secretNamespace: "awesome-namespace",
			secretName:      "awesome-secret",
			secretKey:       "awesome",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"awesome": []byte("pinniped-is-awesome"),
					},
				},
			},
			expectedData: "pinniped-is-awesome",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
			sharedInformers := informers.NewSharedInformerFactory(fakeClient, 0)
			secretsInformer := sharedInformers.Core().V1().Secrets()

			// calling the .Informer function registers this informer in the sharedinformer.
			// doing this will ensure that this informer will be sync'd when Start is called next.
			secretsInformer.Informer()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sharedInformers.Start(ctx.Done())
			sharedInformers.WaitForCacheSync(ctx.Done())
			// now the objects from kubernetes should be sync'd into the informer cache.
			actualData, actualError := readCABundleFromK8sSecret(tt.secretNamespace, tt.secretName, tt.secretKey, secretsInformer)
			if tt.expectError {
				require.Error(t, actualError)
			} else {
				require.NoError(t, actualError)
			}
			require.Equal(t, tt.expectedData, actualData)
		})
	}
}

func TestReadCABundleFromK8sConfigMap(t *testing.T) {
	tests := []struct {
		name               string
		configMapNamespace string
		configMapName      string
		configMapKey       string
		k8sObjects         []runtime.Object
		expectedData       string
		expectError        bool
	}{
		{
			name:               "should return error reading a non-existent configMap",
			configMapNamespace: "awesome-namespace",
			configMapName:      "does-not-exist",
			configMapKey:       "does-not-matter",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"awesome": "pinniped-is-awesome",
					},
				},
			},
			expectedData: "",
			expectError:  true,
		},
		{
			name:               "should return error reading a non-existing key in an existing configMap",
			configMapNamespace: "awesome-namespace",
			configMapName:      "awesome-configmap",
			configMapKey:       "does-not-exist",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"awesome": "pinniped-is-awesome",
					},
				},
			},
			expectedData: "",
			expectError:  true,
		},
		{
			name:               "should return expected data from an existing key in an existing configMap",
			configMapNamespace: "awesome-namespace",
			configMapName:      "awesome-configmap",
			configMapKey:       "awesome",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"awesome": "pinniped-is-awesome",
					},
				},
			},
			expectedData: "pinniped-is-awesome",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)

			sharedInformers := informers.NewSharedInformerFactory(fakeClient, 0)
			configMapInformer := sharedInformers.Core().V1().ConfigMaps()

			// calling the .Informer function registers this informer in the sharedinformer.
			// doing this will ensure that this informer will be sync'd when Start is called next.
			configMapInformer.Informer()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sharedInformers.Start(ctx.Done())
			sharedInformers.WaitForCacheSync(ctx.Done())
			actualData, actualError := readCABundleFromK8sConfigMap(tt.configMapNamespace, tt.configMapName, tt.configMapKey, configMapInformer)
			if tt.expectError {
				require.Error(t, actualError)
			} else {
				require.NoError(t, actualError)
			}
			require.Equal(t, tt.expectedData, actualData)
		})
	}
}

func TestNewCommonTLSSpecForSupervisor(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	bundle := testCA.Bundle()
	base64EncodedBundle := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		name              string
		supervisorTLSSpec *idpv1alpha1.TLSSpec
		expected          *TLSSpec
	}{
		{
			name:              "should return nil spec when supervisorTLSSpec is nil",
			supervisorTLSSpec: nil,
			expected:          nil,
		},
		{
			name: "should return tls spec with non-empty certificateAuthorityData",
			supervisorTLSSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData:       base64EncodedBundle,
				CertificateAuthorityDataSource: nil,
			},
			expected: &TLSSpec{
				CertificateAuthorityData:       base64EncodedBundle,
				CertificateAuthorityDataSource: nil,
			},
		},
		{
			name: "should return tls spec with certificateAuthorityDataSource",
			supervisorTLSSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			expected: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := TLSSpecForSupervisor(tt.supervisorTLSSpec)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestNewCommonTlsSpecForConcierge(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	bundle := testCA.Bundle()
	base64EncodedBundle := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		name             string
		conciergeTLSSpec *authenticationv1alpha1.TLSSpec
		expected         *TLSSpec
	}{
		{
			name:             "should return nil spec when supervisorTLSSpec is nil",
			conciergeTLSSpec: nil,
			expected:         nil,
		},
		{
			name: "should return tls spec with non-empty certificateAuthorityData",
			conciergeTLSSpec: &authenticationv1alpha1.TLSSpec{
				CertificateAuthorityData:       base64EncodedBundle,
				CertificateAuthorityDataSource: nil,
			},
			expected: &TLSSpec{
				CertificateAuthorityData:       base64EncodedBundle,
				CertificateAuthorityDataSource: nil,
			},
		},
		{
			name: "should return tls spec with certificateAuthorityDataSource",
			conciergeTLSSpec: &authenticationv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			expected: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := TlsSpecForConcierge(tt.conciergeTLSSpec)
			require.Equal(t, tt.expected, actual)
		})
	}
}
