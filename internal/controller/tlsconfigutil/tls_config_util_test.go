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
	base64EncodedBundle := base64.StdEncoding.EncodeToString(testCA.Bundle())

	testCABundle, ok := NewCABundle(testCA.Bundle())
	require.True(t, ok)

	tests := []struct {
		name              string
		tlsSpec           *TLSSpec
		namespace         string
		k8sObjects        []runtime.Object
		expectedCABundle  *CABundle
		expectedCondition *metav1.Condition
	}{
		{
			name:    "nil TLSSpec should generate a noTLSConfigurationMessage condition",
			tlsSpec: nil,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: " + noTLSConfigurationMessage,
			},
		},
		{
			name:    "empty inline ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec: &TLSSpec{},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: " + noTLSConfigurationMessage,
			},
		},
		{
			name: "valid base64 encode ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec: &TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
			},
			expectedCABundle: testCABundle,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: " + loadedTLSConfigurationMessage,
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
				Message: `spec.foo.tls.certificateAuthorityData is invalid: no base64-encoded PEM certificates found in 88 bytes of data (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
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
				Message: "spec.foo.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 3",
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
				Message: "spec.foo.tls is invalid: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided",
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
						"ca-bundle": testCA.Bundle(),
					},
				},
			},
			expectedCABundle: testCABundle,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: loaded TLS configuration",
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
						"ca-bundle": testCA.Bundle(),
					},
				},
			},
			expectedCABundle: testCABundle,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: loaded TLS configuration",
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
						"ca-bundle": testCA.Bundle(),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: secret "awesome-namespace/awesome-secret-ba" of type "kubernetes.io/basic-auth" cannot be used as a certificate authority data source`,
			},
		},
		{
			name: "should return invalid condition when a secret does not have the configured key",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"wrong-key": testCA.Bundle(),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" not found in secret "awesome-namespace/awesome-secret"`,
			},
		},
		{
			name: "should return invalid condition when a secret has the configured key but its value is empty",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca-bundle": []byte(""),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" has empty value in secret "awesome-namespace/awesome-secret"`,
			},
		},
		{
			name: "should return invalid condition when a secret has the configured key but the value is not a cert",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-secret",
						Namespace: "awesome-namespace",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca-bundle": []byte("this is not a certificate"),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" with 25 bytes of data in secret "awesome-namespace/awesome-secret" is not a PEM-encoded certificate (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
			},
		},
		{
			name: "should return invalid condition when a configmap does not have the configured key",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "ConfigMap",
					Name: "awesome-configmap",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"wrong-key": string(testCA.Bundle()),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" not found in configmap "awesome-namespace/awesome-configmap"`,
			},
		},
		{
			name: "should return invalid condition when a configmap has the configured key but its value is empty",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "ConfigMap",
					Name: "awesome-configmap",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": "",
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" has empty value in configmap "awesome-namespace/awesome-configmap"`,
			},
		},
		{
			name: "should return invalid condition when a configmap has the configured key but its value not a cert",
			tlsSpec: &TLSSpec{
				CertificateAuthorityDataSource: &caBundleSource{
					Kind: "ConfigMap",
					Name: "awesome-configmap",
					Key:  "ca-bundle",
				},
			},
			namespace: "awesome-namespace",
			k8sObjects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "awesome-configmap",
						Namespace: "awesome-namespace",
					},
					Data: map[string]string{
						"ca-bundle": "this is not a cert",
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: key "ca-bundle" with 18 bytes of data in configmap "awesome-namespace/awesome-configmap" is not a PEM-encoded certificate (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
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
						"ca-bundle": string(testCA.Bundle()),
					},
				},
			},
			expectedCABundle: testCABundle,
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionTrue,
				Reason:  conditionsutil.ReasonSuccess,
				Message: "spec.foo.tls is valid: loaded TLS configuration",
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
			namespace:  "awesome-namespace",
			k8sObjects: []runtime.Object{},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: failed to get secret "awesome-namespace/does-not-exist": secret "does-not-exist" not found`,
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
			namespace:  "awesome-namespace",
			k8sObjects: []runtime.Object{},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: `spec.foo.tls.certificateAuthorityDataSource is invalid: failed to get configmap "awesome-namespace/does-not-exist": configmap "does-not-exist" not found`,
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
						"ca-bundle": string(testCA.Bundle()),
					},
				},
			},
			expectedCondition: &metav1.Condition{
				Type:    typeTLSConfigurationValid,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidTLSConfig,
				Message: "spec.foo.tls.certificateAuthorityDataSource is invalid: unsupported CA bundle source kind: SomethingElse",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var secretsInformer corev1informers.SecretInformer
			var configMapInformer corev1informers.ConfigMapInformer

			fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
			sharedInformers := informers.NewSharedInformerFactory(fakeClient, 0)
			configMapInformer = sharedInformers.Core().V1().ConfigMaps()
			secretsInformer = sharedInformers.Core().V1().Secrets()

			// Calling the Informer() function registers this informer in the sharedinformer.
			// Doing this will ensure that this informer will be sync'd when Start() is called.
			// This is needed in this test because we are not using the controller library here,
			// which would do these same calls for us.
			configMapInformer.Informer()
			secretsInformer.Informer()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sharedInformers.Start(ctx.Done())
			// This is needed in this test because we are not using the controller library here,
			// which would do this same call for us.
			sharedInformers.WaitForCacheSync(ctx.Done())

			actualCondition, actualBundle := ValidateTLSConfig(tt.tlsSpec, "spec.foo.tls", tt.namespace, secretsInformer, configMapInformer)

			require.Equal(t, tt.expectedCondition, actualCondition)
			if tt.expectedCABundle != nil {
				require.True(t, tt.expectedCABundle.IsEqual(actualBundle), "expectedCertPool did not equal actualCertPool")
			}
		})
	}
}

func TestTLSSpecForSupervisor(t *testing.T) {
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
		{
			name: "should return tls spec when source has all fields filled",
			supervisorTLSSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			expected: &TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
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

func TestTLSSpecForConcierge(t *testing.T) {
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
			name:             "should return nil spec when TLSSpec is nil",
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
		{
			name: "should return tls spec when source has all fields filled",
			conciergeTLSSpec: &authenticationv1alpha1.TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
				CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: "awesome-secret",
					Key:  "ca-bundle",
				},
			},
			expected: &TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
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
			actual := TLSSpecForConcierge(tt.conciergeTLSSpec)
			require.Equal(t, tt.expected, actual)
		})
	}
}
