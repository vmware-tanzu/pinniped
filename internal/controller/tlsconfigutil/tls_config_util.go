// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/controller/conditionsutil"
)

const (
	ReasonInvalidTLSConfig = "InvalidTLSConfig"

	noTLSConfigurationMessage     = "no TLS configuration provided: using default root CA bundle from container image"
	loadedTLSConfigurationMessage = "using configured CA bundle"
	typeTLSConfigurationValid     = "TLSConfigurationValid"
)

type caBundleSource struct {
	Kind string
	Name string
	Key  string
}

// TLSSpec unifies the TLSSpec type that Supervisor and Concierge both individually define.
// unifying these two definitions to allow sharing code that will read the spec and translate it into a CA bundle.
type TLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle). If omitted, a default set of system roots will be trusted.
	CertificateAuthorityData string
	// Reference to a CA bundle in a secret or a configmap.
	CertificateAuthorityDataSource *caBundleSource
}

// TLSSpecForSupervisor is a helper function to convert the Supervisor's TLSSpec to the unified TLSSpec.
func TLSSpecForSupervisor(source *idpv1alpha1.TLSSpec) *TLSSpec {
	if source == nil {
		return nil
	}
	dest := &TLSSpec{
		CertificateAuthorityData: source.CertificateAuthorityData,
	}

	if source.CertificateAuthorityDataSource != nil {
		dest.CertificateAuthorityDataSource = &caBundleSource{
			Kind: string(source.CertificateAuthorityDataSource.Kind),
			Name: source.CertificateAuthorityDataSource.Name,
			Key:  source.CertificateAuthorityDataSource.Key,
		}
	}

	return dest
}

// TLSSpecForConcierge is a helper function to convert the Concierge's TLSSpec to the unified TLSSpec.
func TLSSpecForConcierge(source *authenticationv1alpha1.TLSSpec) *TLSSpec {
	if source == nil {
		return nil
	}
	dest := &TLSSpec{
		CertificateAuthorityData: source.CertificateAuthorityData,
	}
	if source.CertificateAuthorityDataSource != nil {
		dest.CertificateAuthorityDataSource = &caBundleSource{
			Kind: string(source.CertificateAuthorityDataSource.Kind),
			Name: source.CertificateAuthorityDataSource.Name,
			Key:  source.CertificateAuthorityDataSource.Key,
		}
	}
	return dest
}

// ValidateTLSConfig reads ca bundle in the tlsSpec, supplied either inline using the CertificateAuthorityDate
// or as a reference to a kubernetes secret or configmap using the CertificateAuthorityDataSource, and returns
// - a condition of type TLSConfigurationValid based on the validity of the ca bundle,
// - a CABundle - an abstraction of internal representation of CA certificate bundles.
func ValidateTLSConfig(
	tlsSpec *TLSSpec,
	conditionPrefix string,
	namespace string,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
) (*metav1.Condition, *CABundle) {
	caBundle, err := buildCABundle(tlsSpec, conditionPrefix, namespace, secretInformer, configMapInformer)
	if err != nil {
		return invalidTLSCondition(err.Error()), nil
	}
	if len(caBundle.PEMBytes()) == 0 {
		// An empty or nil CA bundle results in a valid TLS condition which indicates that no CA data was supplied.
		return validTLSCondition(fmt.Sprintf("%s is valid: %s", conditionPrefix, noTLSConfigurationMessage)), nil
	}
	return validTLSCondition(fmt.Sprintf("%s is valid: %s", conditionPrefix, loadedTLSConfigurationMessage)),
		caBundle
}

// buildCABundle reads the unified tlsSpec and returns an X509 cert pool with the CA data that is read either from
// the inline tls.certificateAuthorityData or from a kubernetes secret or a config map as specified in the
// tls.certificateAuthorityDataSource.
// If the provided tlsSpec is nil, a nil CA bundle will be returned.
// If the provided spec contains a CA bundle that is not properly encoded, an error will be returned.
func buildCABundle(
	tlsSpec *TLSSpec,
	conditionPrefix string,
	namespace string,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
) (*CABundle, error) {
	// if tlsSpec is nil, we return a nil cert pool and cert bundle. A nil error is also returned to indicate that
	// a nil tlsSpec is nevertheless a valid one resulting in a valid TLS condition.
	if tlsSpec == nil {
		return nil, nil
	}

	// it is a configuration error to specify a ca bundle inline using the tls.certificateAuthorityDataSource field
	// and also specifying a kubernetes secret or a config map to serve as the source for the ca bundle.
	if len(tlsSpec.CertificateAuthorityData) > 0 && tlsSpec.CertificateAuthorityDataSource != nil {
		return nil, fmt.Errorf("%s is invalid: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided", conditionPrefix)
	}

	var err error
	var caBundleAsBytes []byte
	var originalCABundleLength int

	type generateErrorForNoCertsInNonEmptyBundleFunc func() error
	var generateErrorForNoCertsInNonEmptyBundle generateErrorForNoCertsInNonEmptyBundleFunc

	if tlsSpec.CertificateAuthorityDataSource != nil {
		// CA data read from kubernetes secrets or config maps will not be base64 encoded.
		// For kubernetes secrets, secret data read using the client-go code automatically decodes base64 encoded values.

		// track the path of the field in the tlsSpec from which the CA data is sourced.
		// this will be used to report in the condition status in case an invalid TLS condition is encountered.
		field := fmt.Sprintf("%s.%s", conditionPrefix, "certificateAuthorityDataSource")
		var bundleAsString string
		bundleAsString, err = readCABundleFromSource(tlsSpec.CertificateAuthorityDataSource, namespace, secretInformer, configMapInformer)
		if err != nil {
			return nil, fmt.Errorf("%s is invalid: %s", field, err.Error())
		}
		caBundleAsBytes = []byte(bundleAsString)
		originalCABundleLength = len(bundleAsString)

		generateErrorForNoCertsInNonEmptyBundle = func() error {
			namespacedName := fmt.Sprintf("%s/%s", namespace, tlsSpec.CertificateAuthorityDataSource.Name)

			return fmt.Errorf(`%s is invalid: key %q with %d bytes of data in %s %q is not a PEM-encoded certificate (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
				field, tlsSpec.CertificateAuthorityDataSource.Key, originalCABundleLength, strings.ToLower(tlsSpec.CertificateAuthorityDataSource.Kind), namespacedName)
		}
	} else {
		// the ca data supplied inline in the CRDs is expected to be base64 encoded.
		field := fmt.Sprintf("%s.%s", conditionPrefix, "certificateAuthorityData")
		var decodedBytes []byte
		decodedBytes, err = base64.StdEncoding.DecodeString(tlsSpec.CertificateAuthorityData)
		if err != nil {
			return nil, fmt.Errorf("%s is invalid: %s", field, err.Error())
		}

		caBundleAsBytes = decodedBytes
		originalCABundleLength = len(tlsSpec.CertificateAuthorityData)

		generateErrorForNoCertsInNonEmptyBundle = func() error {
			return fmt.Errorf("%s is invalid: no base64-encoded PEM certificates found in %d bytes of data (PEM certificates must begin with \"-----BEGIN CERTIFICATE-----\")",
				field, originalCABundleLength)
		}
	}

	// It is perfectly valid to have an empty CA bundle
	if originalCABundleLength == 0 {
		return nil, nil
	}

	caBundle, ok := NewCABundle(caBundleAsBytes)
	if !ok {
		return nil, generateErrorForNoCertsInNonEmptyBundle()
	}

	return caBundle, nil
}

func readCABundleFromSource(source *caBundleSource, namespace string, secretInformer corev1informers.SecretInformer, configMapInformer corev1informers.ConfigMapInformer) (string, error) {
	switch source.Kind {
	case "Secret":
		return readCABundleFromK8sSecret(namespace, source.Name, source.Key, secretInformer)
	case "ConfigMap":
		return readCABundleFromK8sConfigMap(namespace, source.Name, source.Key, configMapInformer)
	default:
		return "", fmt.Errorf("unsupported CA bundle source kind: %s", source.Kind)
	}
}

func readCABundleFromK8sSecret(namespace string, name string, key string, secretInformer corev1informers.SecretInformer) (string, error) {
	namespacedName := fmt.Sprintf("%s/%s", namespace, name)

	s, err := secretInformer.Lister().Secrets(namespace).Get(name)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get secret %q", namespacedName)
	}

	// For Secrets to be used as a certificate authority data source, the secret should be of type
	// kubernetes.io/tls or Opaque. It is an error to use a secret that is of any other type.
	if s.Type != corev1.SecretTypeTLS && s.Type != corev1.SecretTypeOpaque {
		return "", fmt.Errorf("secret %q of type %q cannot be used as a certificate authority data source", namespacedName, s.Type)
	}

	val, exists := s.Data[key]
	if !exists {
		return "", fmt.Errorf("key %q not found in secret %q", key, namespacedName)
	}
	if len(val) == 0 {
		return "", fmt.Errorf("key %q has empty value in secret %q", key, namespacedName)
	}
	return string(val), nil
}

func readCABundleFromK8sConfigMap(namespace string, name string, key string, configMapInformer corev1informers.ConfigMapInformer) (string, error) {
	namespacedName := fmt.Sprintf("%s/%s", namespace, name)

	c, err := configMapInformer.Lister().ConfigMaps(namespace).Get(name)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get configmap %q", namespacedName)
	}

	val, exists := c.Data[key]
	if !exists {
		return "", fmt.Errorf("key %q not found in configmap %q", key, namespacedName)
	}
	if len(val) == 0 {
		return "", fmt.Errorf("key %q has empty value in configmap %q", key, namespacedName)
	}
	return val, nil
}

func validTLSCondition(message string) *metav1.Condition {
	return &metav1.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: message,
	}
}

func invalidTLSCondition(message string) *metav1.Condition {
	return &metav1.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonInvalidTLSConfig,
		Message: message,
	}
}
