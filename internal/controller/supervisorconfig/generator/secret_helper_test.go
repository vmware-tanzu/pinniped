// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
)

const keyWith32Bytes = "0123456789abcdef0123456789abcdef"

func TestSymmetricSecretHelper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                         string
		secretUsage                  SecretUsage
		wantSecretType               corev1.SecretType
		wantSetFederationDomainField func(*configv1alpha1.FederationDomain) string
	}{
		{
			name:           "token signing key",
			secretUsage:    SecretUsageTokenSigningKey,
			wantSecretType: "secrets.pinniped.dev/federation-domain-token-signing-key",
			wantSetFederationDomainField: func(federationDomain *configv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.TokenSigningKey.Name
			},
		},
		{
			name:           "state signing key",
			secretUsage:    SecretUsageStateSigningKey,
			wantSecretType: "secrets.pinniped.dev/federation-domain-state-signing-key",
			wantSetFederationDomainField: func(federationDomain *configv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.StateSigningKey.Name
			},
		},
		{
			name:           "state encryption key",
			secretUsage:    SecretUsageStateEncryptionKey,
			wantSecretType: "secrets.pinniped.dev/federation-domain-state-encryption-key",
			wantSetFederationDomainField: func(federationDomain *configv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.StateEncryptionKey.Name
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			labels := map[string]string{
				"some-label-key-1": "some-label-value-1",
				"some-label-key-2": "some-label-value-2",
			}
			randSource := strings.NewReader(keyWith32Bytes)
			var federationDomainIssuerValue string
			var symmetricKeyValue []byte
			h := NewSymmetricSecretHelper(
				"some-name-prefix-",
				labels,
				randSource,
				test.secretUsage,
				func(federationDomainIssuer string, symmetricKey []byte) {
					require.True(t, federationDomainIssuer == "" && symmetricKeyValue == nil, "expected notify func not to have been called yet")
					federationDomainIssuerValue = federationDomainIssuer
					symmetricKeyValue = symmetricKey
				},
			)

			parent := &configv1alpha1.FederationDomain{
				ObjectMeta: metav1.ObjectMeta{
					UID:       "some-uid",
					Namespace: "some-namespace",
				},
			}
			child, err := h.Generate(parent)
			require.NoError(t, err)
			require.Equal(t, child, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-name-prefix-some-uid",
					Namespace: "some-namespace",
					Labels:    labels,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(parent, schema.GroupVersionKind{
							Group:   configv1alpha1.SchemeGroupVersion.Group,
							Version: configv1alpha1.SchemeGroupVersion.Version,
							Kind:    "FederationDomain",
						}),
					},
				},
				Type: test.wantSecretType,
				Data: map[string][]byte{
					"key": []byte(keyWith32Bytes),
				},
			})

			require.True(t, h.IsValid(parent, child))

			h.ObserveActiveSecretAndUpdateParentFederationDomain(parent, child)
			require.Equal(t, parent.Spec.Issuer, federationDomainIssuerValue)
			require.Equal(t, child.Name, test.wantSetFederationDomainField(parent))
			require.Equal(t, child.Data["key"], symmetricKeyValue)

			require.True(t, h.Handles(child))
			wrongTypedChild := child.DeepCopy()
			wrongTypedChild.Type = "the-wrong-type"
			require.False(t, h.Handles(wrongTypedChild))
			wrongOwnerKindChild := child.DeepCopy()
			wrongOwnerKindChild.OwnerReferences[0].Kind = "WrongKind"
			require.False(t, h.Handles(wrongOwnerKindChild))
		})
	}
}

func TestSymmetricSecretHelperIsValid(t *testing.T) {
	tests := []struct {
		name        string
		secretUsage SecretUsage
		child       func(*corev1.Secret)
		parent      func(*configv1alpha1.FederationDomain)
		want        bool
	}{
		{
			name:        "wrong type",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = "wrong"
			},
			want: false,
		},
		{
			name:        "empty type",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = ""
			},
			want: false,
		},
		{
			name:        "data key is too short",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = FederationDomainTokenSigningKeyType
				s.Data["key"] = []byte("short")
			},
			want: false,
		},
		{
			name:        "data key does not exist",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = FederationDomainTokenSigningKeyType
				delete(s.Data, "key")
			},
			want: false,
		},
		{
			name:        "child not owned by parent",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = FederationDomainTokenSigningKeyType
			},
			parent: func(federationDomain *configv1alpha1.FederationDomain) {
				federationDomain.UID = "wrong"
			},
			want: false,
		},
		{
			name:        "happy path",
			secretUsage: SecretUsageTokenSigningKey,
			child: func(s *corev1.Secret) {
				s.Type = FederationDomainTokenSigningKeyType
			}, want: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			h := NewSymmetricSecretHelper("none of these args matter", nil, nil, test.secretUsage, nil)

			parent := &configv1alpha1.FederationDomain{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-parent-name",
					Namespace: "some-namespace",
					UID:       "some-parent-uid",
				},
			}
			child := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-name-prefix-some-uid",
					Namespace: "some-namespace",
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(parent, schema.GroupVersionKind{
							Group:   configv1alpha1.SchemeGroupVersion.Group,
							Version: configv1alpha1.SchemeGroupVersion.Version,
							Kind:    "FederationDomain",
						}),
					},
				},
				Type: "invalid default",
				Data: map[string][]byte{
					"key": []byte(keyWith32Bytes),
				},
			}
			if test.child != nil {
				test.child(child)
			}
			if test.parent != nil {
				test.parent(parent)
			}

			require.Equalf(t, test.want, h.IsValid(parent, child), "child: %#v", child)
		})
	}
}
