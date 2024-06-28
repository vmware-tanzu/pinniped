// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/cert"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/controllerlib"
)

func NameAndNamespaceExactMatchFilterFactory(name, namespace string) controllerlib.Filter {
	return SimpleFilter(func(obj metav1.Object) bool {
		return obj.GetName() == name && obj.GetNamespace() == namespace
		// nil parent func is fine because we only match a key with the given name and namespace
		// i.e. it is equivalent to having a SingletonQueue() parent func
	}, nil)
}

// MatchAnythingIgnoringUpdatesFilter returns a controllerlib.Filter that allows all objects but ignores updates.
func MatchAnythingIgnoringUpdatesFilter(parentFunc controllerlib.ParentFunc) controllerlib.Filter {
	return controllerlib.FilterFuncs{
		AddFunc:    func(_ metav1.Object) bool { return true },
		UpdateFunc: func(_oldObj, _newObj metav1.Object) bool { return false },
		DeleteFunc: func(_ metav1.Object) bool { return true },
		ParentFunc: parentFunc,
	}
}

// MatchAnythingFilter returns a controllerlib.Filter that allows all objects.
func MatchAnythingFilter(parentFunc controllerlib.ParentFunc) controllerlib.Filter {
	return SimpleFilter(func(_ metav1.Object) bool { return true }, parentFunc)
}

// SimpleFilter takes a single boolean match function on a metav1.Object and wraps it into a proper controllerlib.Filter.
func SimpleFilter(match func(metav1.Object) bool, parentFunc controllerlib.ParentFunc) controllerlib.Filter {
	return controllerlib.FilterFuncs{
		AddFunc:    match,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool { return match(oldObj) || match(newObj) },
		DeleteFunc: match,
		ParentFunc: parentFunc,
	}
}

func MatchAnySecretOfTypeFilter(secretType corev1.SecretType, parentFunc controllerlib.ParentFunc, namespaces ...string) controllerlib.Filter {
	isSecretOfType := func(obj metav1.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		// Only match on namespace if namespaces are provided
		if len(namespaces) > 0 && !slices.Contains(namespaces, secret.Namespace) {
			return false
		}
		return secret.Type == secretType
	}
	return SimpleFilter(isSecretOfType, parentFunc)
}

func MatchAnySecretOfTypesFilter(secretTypes []corev1.SecretType, parentFunc controllerlib.ParentFunc, namespaces ...string) controllerlib.Filter {
	isSecretOfType := func(obj metav1.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		// Only match on namespace if namespaces are provided
		if len(namespaces) > 0 && !slices.Contains(namespaces, secret.Namespace) {
			return false
		}
		return slices.Contains(secretTypes, secret.Type)
	}
	return SimpleFilter(isSecretOfType, parentFunc)
}

func SecretIsControlledByParentFunc(matchFunc func(obj metav1.Object) bool) func(obj metav1.Object) controllerlib.Key {
	return func(obj metav1.Object) controllerlib.Key {
		if matchFunc(obj) {
			controller := metav1.GetControllerOf(obj)
			return controllerlib.Key{
				Name:      controller.Name,
				Namespace: obj.GetNamespace(),
			}
		}
		return controllerlib.Key{}
	}
}

// SingletonQueue returns a parent func that treats all events as the same key.
func SingletonQueue() controllerlib.ParentFunc {
	return func(_ metav1.Object) controllerlib.Key {
		return controllerlib.Key{}
	}
}

// SimpleFilterWithSingletonQueue returns a Filter based on the given match function that treats all events as the same key.
func SimpleFilterWithSingletonQueue(match func(metav1.Object) bool) controllerlib.Filter {
	return SimpleFilter(match, SingletonQueue())
}

// Same signature as controllerlib.WithInformer().
type WithInformerOptionFunc func(
	getter controllerlib.InformerGetter,
	filter controllerlib.Filter,
	opt controllerlib.InformerOption) controllerlib.Option

// Same signature as controllerlib.WithInitialEvent().
type WithInitialEventOptionFunc func(key controllerlib.Key) controllerlib.Option

// BuildCertPoolAuth returns a PEM-encoded CA bundle from the provided spec. If the provided spec is nil, a
// nil CA bundle will be returned. If the provided spec contains a CA bundle that is not properly
// encoded, an error will be returned.
func BuildCertPoolAuth(spec *authenticationv1alpha1.TLSSpec) (*x509.CertPool, []byte, error) {
	if spec == nil {
		return nil, nil, nil
	}

	return buildCertPool(spec.CertificateAuthorityData)
}

// BuildCertPoolIDP returns a PEM-encoded CA bundle from the provided spec. If the provided spec is nil, a
// nil CA bundle will be returned. If the provided spec contains a CA bundle that is not properly
// encoded, an error will be returned.
func BuildCertPoolIDP(spec *idpv1alpha1.TLSSpec) (*x509.CertPool, []byte, error) {
	if spec == nil {
		return nil, nil, nil
	}

	return buildCertPool(spec.CertificateAuthorityData)
}

func buildCertPool(certificateAuthorityData string) (*x509.CertPool, []byte, error) {
	if len(certificateAuthorityData) == 0 {
		return nil, nil, nil
	}

	pem, err := base64.StdEncoding.DecodeString(certificateAuthorityData)
	if err != nil {
		return nil, nil, err
	}

	rootCAs, err := cert.NewPoolFromBytes(pem)
	if err != nil {
		return nil, nil, fmt.Errorf("certificateAuthorityData is not valid PEM: %w", err)
	}

	return rootCAs, pem, nil
}
