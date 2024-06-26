// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
)

func TestValidateTLSConfig(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	bundle := testCA.Bundle()
	base64EncodedBundle := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		name              string
		tlsSpec           *idpv1alpha1.TLSSpec
		namespace         string
		k8sObjects        []runtime.Object
		expectedCondition *metav1.Condition
		expectError       bool
	}{
		{
			name:              "nil TLSSpec should generate a noTLSConfigurationMessage condition",
			tlsSpec:           nil,
			expectedCondition: validTLSCondition(noTLSConfigurationMessage),
			expectError:       false,
		},
		{
			name:              "empty inline ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec:           &idpv1alpha1.TLSSpec{},
			expectedCondition: validTLSCondition(loadedTLSConfigurationMessage),
			expectError:       false,
		},
		{
			name: "valid base64 encode ca data should generate a loadedTLSConfigurationMessage condition",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
			},
			expectedCondition: validTLSCondition(loadedTLSConfigurationMessage),
			expectError:       false,
		},
		{
			name: "valid base64 encoded non cert data should generate a invalidTLSCondition condition",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: "dGhpcyBpcyBzb21lIHRlc3QgZGF0YSB0aGF0IGlzIGJhc2U2NCBlbmNvZGVkIHRoYXQgaXMgbm90IGEgY2VydAo=",
			},
			expectedCondition: invalidTLSCondition(fmt.Sprintf("certificateAuthorityData is invalid: %s", ErrNoCertificates)),
			expectError:       true,
		},
		{
			name: "non-base64 encoded string as ca data should generate an invalidTLSCondition condition",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: "non base64 encoded string",
			},
			expectedCondition: invalidTLSCondition("certificateAuthorityData is invalid: illegal base64 data"),
			expectError:       true,
		},
		{
			name: "supplying certificateAuthorityDataSource and certificateAuthorityData should generate an invalid condition",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64EncodedBundle,
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
					Kind: "Secret",
					Name: "super-secret",
					Key:  "ca-base64EncodedBundle",
				},
			},
			expectedCondition: invalidTLSCondition("tls spec config error: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided."),
			expectError:       true,
		},
		{
			name: "should return ca bundle from kubernetes secret",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
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
					Data: map[string][]byte{
						"ca-bundle": []byte(bundle),
					},
				},
			},
			expectedCondition: validTLSCondition(fmt.Sprintf("tls is valid: %s", loadedTLSConfigurationMessage)),
			expectError:       false,
		},
		{
			name: "should return ca bundle from kubernetes configMap",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
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
			expectedCondition: validTLSCondition(fmt.Sprintf("tls is valid: %s", loadedTLSConfigurationMessage)),
			expectError:       false,
		},
		{
			name: "should return invalid condition when failing to read ca bundle from kubernetes secret that does not exist",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
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
			expectedCondition: invalidTLSCondition("tls.certificateAuthorityDataSource is invalid: failed to read from source"),
			expectError:       true,
		},
		{
			name: "should return invalid condition when failing to read ca bundle from kubernetes configMap that does not exist",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
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
			expectedCondition: invalidTLSCondition("tls.certificateAuthorityDataSource is invalid: failed to read from source"),
			expectError:       true,
		},
		{
			name: "should return invalid condition when using an invalid certificate authority data source",
			tlsSpec: &idpv1alpha1.TLSSpec{
				CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
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
			expectedCondition: invalidTLSCondition("tls.certificateAuthorityDataSource is invalid: unsupported CA bundle source"),
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var secretsInformer corev1informers.SecretInformer
			var configMapInformer corev1informers.ConfigMapInformer

			if len(tt.k8sObjects) > 0 {
				stopSecretInformer := make(chan struct{})
				stopConfigMapInformer := make(chan struct{})
				fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
				sharedInformers := informers.NewSharedInformerFactory(fakeClient, time.Second)
				configMapInformer = sharedInformers.Core().V1().ConfigMaps()
				secretsInformer = sharedInformers.Core().V1().Secrets()

				// Run the informer so that it can sync the objects from kubernetes into its cache.
				// run as a go routine so that we can stop the informer and continue with our tests.
				go secretsInformer.Informer().Run(stopSecretInformer)
				// wait 1s before stopping the informer. 1s because, that's the resync duration of the informer.
				time.Sleep(time.Second)
				close(stopSecretInformer)
				// TODO: can we avoid calling Run on both informers?
				go configMapInformer.Informer().Run(stopConfigMapInformer)
				time.Sleep(time.Second)
				close(stopConfigMapInformer)
				// now the objects from kubernetes should be sync'd into the informer cache.
			}
			actualCondition, _, _, err := ValidateTLSConfig(tt.tlsSpec, "tls", tt.namespace, secretsInformer, configMapInformer)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedCondition.Type, actualCondition.Type)
				require.Equal(t, tt.expectedCondition.Status, actualCondition.Status)
				require.Equal(t, tt.expectedCondition.Reason, actualCondition.Reason)
			}
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
			name:            "should return data from existing secret and existing key",
			secretNamespace: "awesome-namespace",
			secretName:      "awesome-secret",
			secretKey:       "awesome",
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
			expectedData: "pinniped-is-awesome",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stop := make(chan struct{})
			fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
			secretsInformer := informers.NewSharedInformerFactory(fakeClient, time.Second).Core().V1().Secrets()
			// Run the informer so that it can sync the objects from kubernetes into its cache.
			// run as a go routine so that we can stop the informer and continue with our tests.
			go secretsInformer.Informer().Run(stop)
			// wait 1s before stopping the informer. 1s because, that's the resync duration of the informer.
			time.Sleep(time.Second)
			close(stop)
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
			stop := make(chan struct{})
			fakeClient := fake.NewSimpleClientset(tt.k8sObjects...)
			configMapInformer := informers.NewSharedInformerFactory(fakeClient, time.Second).Core().V1().ConfigMaps()

			// Run the informer so that it can sync the objects from kubernetes into its cache.
			// run as a go routine so that we can stop the informer and continue with our tests.
			go configMapInformer.Informer().Run(stop)
			// wait 1s before stopping the informer. 1s because, that's the resync duration of the informer.
			time.Sleep(time.Second)
			close(stop)
			// now the objects from kubernetes should be sync'd into the informer cache.
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
