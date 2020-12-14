// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"crypto/rand"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
)

const (
	symmetricKeySecretType    = "secrets.pinniped.dev/symmetric"
	symmetricKeySecretDataKey = "key"

	symmetricKeySize = 32

	opKind = "OIDCProvider"
)

func generateSymmetricKey() ([]byte, error) {
	b := make([]byte, symmetricKeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func isValid(secret *corev1.Secret) bool {
	if secret.Type != symmetricKeySecretType {
		return false
	}

	data, ok := secret.Data[symmetricKeySecretDataKey]
	if !ok {
		return false
	}
	if len(data) != symmetricKeySize {
		return false
	}

	return true
}

func secretDataFunc() (map[string][]byte, error) {
	symmetricKey, err := generateKey()
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		symmetricKeySecretDataKey: symmetricKey,
	}, nil
}

func generateSecret(namespace, name string, labels map[string]string, secretDataFunc func() (map[string][]byte, error), owner metav1.Object) (*corev1.Secret, error) {
	secretData, err := secretDataFunc()
	if err != nil {
		return nil, err
	}

	deploymentGVK := schema.GroupVersionKind{
		Group:   appsv1.SchemeGroupVersion.Group,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    "Deployment",
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(owner, deploymentGVK),
			},
			Labels: labels,
		},
		Type: symmetricKeySecretType,
		Data: secretData,
	}, nil
}

// isOPCControlle returns whether the provided obj is controlled by an OPC.
func isOPControllee(obj metav1.Object) bool {
	controller := metav1.GetControllerOf(obj)
	return controller != nil &&
		controller.APIVersion == configv1alpha1.SchemeGroupVersion.String() &&
		controller.Kind == opKind
}
