// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controller/conditionsutil"
)

const (
	ReasonInvalidTLSConfig = "InvalidTLSConfig"

	noTLSConfigurationMessage     = "no TLS configuration provided"
	loadedTLSConfigurationMessage = "loaded TLS configuration"
	typeTLSConfigurationValid     = "TLSConfigurationValid"

	ErrNoCertificates = constable.Error("no certificates found")
)

// BuildCertPoolIDP reads the tlsSpec of the IDP and returns an X509 cert pool with the CA data that is read either from
// the inline tls.certificateAuthorityData or from a kubernetes secret or a config map as specified in the
// tls.certificateAuthorityDataSource.
// If the provided tlsSpec is nil, a nil CA bundle will be returned.
// If the provided spec contains a CA bundle that is not properly encoded, an error will be returned.
// TODO: should this function be exposed outside this package?
func BuildCertPoolIDP(
	tlsSpec *v1alpha1.TLSSpec,
	conditionPrefix string,
	namespace string,
	secretInformer v1.SecretInformer,
	configMapInformer v1.ConfigMapInformer,
) (*x509.CertPool, []byte, error) {
	// if tlsSpec is nil, we return a nil cert pool and cert bundle. A nil error is also returned to indicate that
	// a nil tlsSpec is nevertheless a valid one resulting in a valid TLS condition.
	if tlsSpec == nil {
		return nil, nil, nil
	}

	// it is a configuration error to specify a ca bundle inline using the tls.certificateAuthorityDataSource field
	// and also specifying a kubernetes secret or a config map to serve as the source for the ca bundle.
	if len(tlsSpec.CertificateAuthorityData) > 0 && tlsSpec.CertificateAuthorityDataSource != nil {
		return nil, nil, fmt.Errorf("%s is invalid: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided", conditionPrefix)
	}

	var err error
	caBundle := tlsSpec.CertificateAuthorityData
	field := fmt.Sprintf("%s.%s", conditionPrefix, "certificateAuthorityData")
	// currently, the ca data supplied inline in the CRDs is expected to be base64 encoded.
	// However, the ca data read from kubernetes secrets or config map will not be base64 encoded.
	// For kubernetes secrets, secret data read using the  client-go code automatically decodes base64 encoded values.
	// So a base64 decode is required only when fetching ca bundle from the tls.certificateAuthorityData field.
	decodeRequired := true
	if tlsSpec.CertificateAuthorityDataSource != nil {
		decodeRequired = false
		// track the path of the field in the tlsSpec from which the CA data is sourced.
		// this will be used to report in the condition status in case an invalid TLS condition is encountered.
		field = fmt.Sprintf("%s.%s", conditionPrefix, "certificateAuthorityDataSource")
		caBundle, err = readCABundleFromSource(tlsSpec.CertificateAuthorityDataSource, namespace, secretInformer, configMapInformer)
		if err != nil {
			return nil, nil, fmt.Errorf("%s is invalid: failed to read CA bundle from source %s/%s/%s: %s",
				field, tlsSpec.CertificateAuthorityDataSource.Kind, tlsSpec.CertificateAuthorityDataSource.Name,
				tlsSpec.CertificateAuthorityDataSource.Key, err.Error())
		}
	}

	if len(caBundle) == 0 {
		return nil, nil, nil
	}

	bundleBytes := []byte(caBundle)
	if decodeRequired {
		bundleBytes, err = base64.StdEncoding.DecodeString(caBundle)
		if err != nil {
			return nil, nil, fmt.Errorf("%s is invalid: %s", conditionPrefix, err.Error())
		}
	}

	// try to create a cert pool with the read ca data to determine validity of the ca bundle read from the tlsSpec.
	ca := x509.NewCertPool()
	ok := ca.AppendCertsFromPEM(bundleBytes)
	if !ok {
		return nil, nil, fmt.Errorf("%s is invalid: %s", field, ErrNoCertificates)
	}

	return ca, bundleBytes, nil
}

// ValidateTLSConfig reads ca bundle in the tlsSpec, supplied either inline using the CertificateAuthorityDate
// or as a reference to a kubernetes secret or configmap using the CertificateAuthorityDataSource, and returns
// a condition of type TLSConfigurationValid based on the validity of the ca bundle,
// a pem encoded ca bundle
// a X509 cert pool with the ca bundle
// any error encountered.
// TODO: it should suffice that this function returns a TLSConfigurationValid condition, and perhaps we could skip
// returning the error. This can be done once all controllers are able to use this function.
func ValidateTLSConfig(
	tlsSpec *v1alpha1.TLSSpec,
	conditionPrefix string,
	namespace string,
	secretInformer v1.SecretInformer,
	configMapInformer v1.ConfigMapInformer,
) (*v12.Condition, []byte, *x509.CertPool, error) {
	// try to build a x509 cert pool using the ca data specified in the tlsSpec.
	certPool, bundle, err := BuildCertPoolIDP(tlsSpec, conditionPrefix, namespace, secretInformer, configMapInformer)
	if err != nil {
		// an error encountered during building a certpool using the ca data from the tlsSpec results in an invalid
		// TLS condition.
		return invalidTLSCondition(err.Error()), nil, nil, err
	}
	// for us, an empty or nil ca bundle read is results in a valid TLS condition, but we do want to convey that
	// no ca data was supplied.
	if bundle == nil {
		return validTLSCondition(fmt.Sprintf("%s is valid: %s", conditionPrefix, noTLSConfigurationMessage)), bundle, certPool, err
	}

	return validTLSCondition(fmt.Sprintf("%s is valid: %s", conditionPrefix, loadedTLSConfigurationMessage)), bundle, certPool, err
}

func readCABundleFromSource(source *v1alpha1.CABundleSource, namespace string, secretInformer v1.SecretInformer, configMapInformer v1.ConfigMapInformer) (string, error) {
	switch source.Kind {
	case "Secret":
		return readCABundleFromK8sSecret(namespace, source.Name, source.Key, secretInformer)
	case "ConfigMap":
		return readCABundleFromK8sConfigMap(namespace, source.Name, source.Key, configMapInformer)
	default:
		return "", fmt.Errorf("unsupported CA bundle source: %s", source.Kind)
	}
}

func readCABundleFromK8sSecret(namespace string, name string, key string, secretInformer v1.SecretInformer) (string, error) {
	s, err := secretInformer.Lister().Secrets(namespace).Get(name)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get secret %s/%s", namespace, name)
	}
	// ca bundle in the secret is expected to exist in a specific key, if that key does not exist, then it is an error
	if val, exists := s.Data[key]; exists {
		return string(val), nil
	}
	return "", fmt.Errorf("key %s not found in secret %s/%s", key, namespace, name)
}

func readCABundleFromK8sConfigMap(namespace string, name string, key string, configMapInformer v1.ConfigMapInformer) (string, error) {
	c, err := configMapInformer.Lister().ConfigMaps(namespace).Get(name)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get configmap %s/%s", namespace, name)
	}

	// ca bundle in the secret is expected to exist in a specific key, if that key does not exist, then it is an error
	if val, exists := c.Data[key]; exists {
		return val, nil
	}
	return "", fmt.Errorf("key %s not found in configmap %s/%s", key, namespace, name)
}

func validTLSCondition(message string) *v12.Condition {
	return &v12.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  v12.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: message,
	}
}

func invalidTLSCondition(message string) *v12.Condition {
	return &v12.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  v12.ConditionFalse,
		Reason:  ReasonInvalidTLSConfig,
		Message: message,
	}
}
